//! `bip110pack` CLI — pack a block with BIP-110-compliant arbitrary data and
//! verify transactions against the BIP-110 compliance checklist.

use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use bitcoin::consensus::encode;
use bitcoin::{Address, Amount, Network, OutPoint, Transaction, Txid};
use clap::{Parser, Subcommand, ValueEnum};
use std::str::FromStr;

use bip110pack::bip110;
use bip110pack::packer;
use bip110pack::taproot_spend;
use bip110pack::tapscript::Auth;

/// CLI-facing spend-authorization mode (maps to [`Auth`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum AuthArg {
    /// Anyone-can-spend (default): envelope terminated with OP_1.
    None,
    /// Require a Schnorr signature from the reveal key via OP_CHECKSIG.
    Checksig,
}

impl From<AuthArg> for Auth {
    fn from(a: AuthArg) -> Self {
        match a {
            AuthArg::None => Auth::None,
            AuthArg::Checksig => Auth::Checksig,
        }
    }
}

/// CLI-facing Bitcoin network selector.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum NetworkArg {
    Regtest,
    Testnet,
    Bitcoin,
}

impl From<NetworkArg> for Network {
    fn from(n: NetworkArg) -> Self {
        match n {
            NetworkArg::Regtest => Network::Regtest,
            NetworkArg::Testnet => Network::Testnet,
            NetworkArg::Bitcoin => Network::Bitcoin,
        }
    }
}

#[derive(Parser)]
#[command(
    name = "bip110pack",
    about = "Maximally pack a Bitcoin block with BIP-110-compliant arbitrary data via Taproot push/OP_2DROP tapscripts",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Pack a data blob into block-ready transactions and report stats.
    Pack {
        /// Input file, or `-` for stdin.
        #[arg(long)]
        input: String,
        /// Optional output file to write the packed tx hex (one tx per line).
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Verify a hex-encoded transaction against the BIP-110 checklist.
    Verify {
        /// Hex-encoded transaction.
        txhex: String,
    },
    /// Recover the embedded arbitrary data from a reveal transaction's witness.
    ///
    /// Reads the tapleaf script (the second-to-last witness item of the first
    /// input) and reconstructs the original bytes. Prints hex to stdout, or the
    /// raw bytes to `--out`.
    Extract {
        /// Hex-encoded transaction.
        txhex: String,
        /// Optional output file for the raw recovered bytes (else hex to stdout).
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Print the P2TR commit address (and scriptPubKey) to fund for a later
    /// data-carrying reveal spend.
    Commit {
        /// Input file, or `-` for stdin (mutually exclusive with --data-hex).
        #[arg(long)]
        input: Option<String>,
        /// Raw data as hex (mutually exclusive with --input).
        #[arg(long)]
        data_hex: Option<String>,
        /// Spend-authorization mode.
        #[arg(long, value_enum, default_value_t = AuthArg::None)]
        auth: AuthArg,
        /// Target network.
        #[arg(long, value_enum, default_value_t = NetworkArg::Regtest)]
        network: NetworkArg,
    },
    /// Build the fully-formed (signed, for checksig) reveal transaction and print
    /// its raw hex to stdout.
    BuildSpend {
        /// Input file, or `-` for stdin (mutually exclusive with --data-hex).
        #[arg(long)]
        input: Option<String>,
        /// Raw data as hex (mutually exclusive with --input).
        #[arg(long)]
        data_hex: Option<String>,
        /// Spend-authorization mode.
        #[arg(long, value_enum, default_value_t = AuthArg::None)]
        auth: AuthArg,
        /// Target network.
        #[arg(long, value_enum, default_value_t = NetworkArg::Regtest)]
        network: NetworkArg,
        /// Previous output being spent, as `txid:vout`.
        #[arg(long)]
        prevout: String,
        /// Value of the previous output, in satoshis.
        #[arg(long)]
        prevout_value: u64,
        /// Fee to pay, in satoshis.
        #[arg(long)]
        fee: u64,
        /// Destination address for the single output.
        #[arg(long)]
        to: String,
    },
}

fn read_input(input: &str) -> Result<Vec<u8>> {
    if input == "-" {
        let mut buf = Vec::new();
        std::io::stdin()
            .read_to_end(&mut buf)
            .context("reading stdin")?;
        Ok(buf)
    } else {
        fs::read(input).with_context(|| format!("reading input file {input}"))
    }
}

fn cmd_pack(input: &str, out: &Option<PathBuf>) -> Result<()> {
    let data = read_input(input)?;
    let res = packer::pack(&data)?;

    let total_hex_len: usize = res.txs.iter().map(|tx| encode::serialize(tx).len()).sum();

    eprintln!("bip110pack: packed {} input byte(s)", data.len());
    eprintln!("  transactions:     {}", res.txs.len());
    eprintln!("  bytes packed:     {}", res.bytes_packed);
    eprintln!(
        "  bytes remaining:  {}",
        data.len().saturating_sub(res.bytes_packed)
    );
    eprintln!(
        "  weight used:      {} WU  (budget {} WU, block limit {} WU)",
        res.weight_used,
        res.budget,
        packer::BLOCK_WEIGHT_LIMIT
    );
    eprintln!(
        "  block fill:       {:.2}%",
        100.0 * res.weight_used as f64 / packer::BLOCK_WEIGHT_LIMIT as f64
    );
    eprintln!(
        "  efficiency:       {:.3}%  (arbitrary data bytes per weight unit)",
        res.efficiency
    );
    eprintln!("  serialized size:  {} bytes", total_hex_len);

    // Independent BIP-110 re-validation of every generated tx.
    for (i, tx) in res.txs.iter().enumerate() {
        match bip110::validate(tx) {
            Ok(()) => {}
            Err(violations) => {
                for v in &violations {
                    eprintln!("  tx {i}: VIOLATION {v}");
                }
                return Err(anyhow!("generated tx {i} failed BIP-110 validation"));
            }
        }
    }
    eprintln!("  BIP-110 check:    all {} tx(s) PASS", res.txs.len());

    let mut sink: Box<dyn Write> = match out {
        Some(path) => Box::new(
            fs::File::create(path).with_context(|| format!("creating {}", path.display()))?,
        ),
        None => Box::new(std::io::stdout()),
    };
    for tx in &res.txs {
        let hexstr = hex::encode(encode::serialize(tx));
        writeln!(sink, "{hexstr}")?;
    }
    Ok(())
}

fn cmd_verify(txhex: &str) -> Result<()> {
    let raw = hex::decode(txhex.trim()).context("decoding tx hex")?;
    let tx: Transaction = encode::deserialize(&raw).context("deserializing transaction")?;

    println!("txid:         {}", tx.compute_txid());
    println!("inputs:       {}", tx.input.len());
    println!("outputs:      {}", tx.output.len());
    println!("weight:       {} WU", tx.weight().to_wu());
    println!("vsize:        {} vB", tx.vsize());

    match bip110::validate(&tx) {
        Ok(()) => {
            println!("BIP-110:      PASS (no violations detected)");
            Ok(())
        }
        Err(violations) => {
            println!("BIP-110:      FAIL ({} violation(s))", violations.len());
            for v in &violations {
                println!("  {v}");
            }
            Err(anyhow!("transaction is NOT BIP-110 compliant"))
        }
    }
}

fn cmd_extract(txhex: &str, out: &Option<PathBuf>) -> Result<()> {
    use bip110pack::tapscript::{extract_data, extract_ord_payload};
    use bitcoin::script::ScriptBuf;

    let raw = hex::decode(txhex.trim()).context("decoding tx hex")?;
    let tx: Transaction = encode::deserialize(&raw).context("deserializing transaction")?;

    let witness = &tx
        .input
        .first()
        .ok_or_else(|| anyhow!("tx has no inputs"))?
        .witness;
    let n = witness.len();
    if n < 2 {
        return Err(anyhow!(
            "input witness has {n} item(s); expected a taproot script-path spend (>=2)"
        ));
    }
    // Taproot script-path witness: [..args, tapleaf_script, control_block].
    // The tapleaf script is the second-to-last item.
    let script_bytes = witness
        .nth(n - 2)
        .ok_or_else(|| anyhow!("missing tapleaf script witness item"))?;
    let script = ScriptBuf::from(script_bytes.to_vec());

    // Prefer the ord-envelope payload (has a PROTOCOL_ID); fall back to the raw
    // push-concatenation used by the `pack` path.
    let mut data = extract_ord_payload(&script);
    if data.is_empty() {
        data = extract_data(&script).map_err(|e| anyhow!(e))?;
    }

    eprintln!(
        "bip110pack: recovered {} data byte(s) from witness",
        data.len()
    );
    match out {
        Some(path) => {
            fs::write(path, &data).with_context(|| format!("writing {}", path.display()))?;
            eprintln!("  wrote raw bytes to {}", path.display());
        }
        None => println!("{}", hex::encode(&data)),
    }
    Ok(())
}

/// Resolve the input bytes from either `--input` (file/stdin) or `--data-hex`.
fn resolve_data(input: &Option<String>, data_hex: &Option<String>) -> Result<Vec<u8>> {
    match (input, data_hex) {
        (Some(_), Some(_)) => Err(anyhow!("provide either --input or --data-hex, not both")),
        (Some(i), None) => read_input(i),
        (None, Some(h)) => hex::decode(h.trim()).context("decoding --data-hex"),
        (None, None) => Err(anyhow!("one of --input or --data-hex is required")),
    }
}

fn cmd_commit(
    input: &Option<String>,
    data_hex: &Option<String>,
    auth: AuthArg,
    network: NetworkArg,
) -> Result<()> {
    let data = resolve_data(input, data_hex)?;
    let net: Network = network.into();
    let addr = taproot_spend::commit_address(&data, auth.into(), net)?;
    let spk = addr.script_pubkey();
    println!("{addr}");
    println!("{}", hex::encode(spk.as_bytes()));
    eprintln!("bip110pack: commit address for {} data byte(s)", data.len());
    eprintln!("  auth:            {auth:?}");
    eprintln!("  network:         {net}");
    eprintln!("  scriptPubKey:    {} bytes", spk.len());
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn cmd_build_spend(
    input: &Option<String>,
    data_hex: &Option<String>,
    auth: AuthArg,
    network: NetworkArg,
    prevout: &str,
    prevout_value: u64,
    fee: u64,
    to: &str,
) -> Result<()> {
    let data = resolve_data(input, data_hex)?;
    let net: Network = network.into();

    // Parse `--prevout` as `txid:vout`.
    let (txid_s, vout_s) = prevout
        .rsplit_once(':')
        .ok_or_else(|| anyhow!("--prevout must be `txid:vout`"))?;
    let txid = Txid::from_str(txid_s).context("parsing prevout txid")?;
    let vout: u32 = vout_s.parse().context("parsing prevout vout")?;
    let outpoint = OutPoint { txid, vout };

    // Parse `--to` as an address for the given network.
    let to_addr = Address::from_str(to)
        .context("parsing --to address")?
        .require_network(net)
        .context("--to address does not match --network")?;
    let to_spk = to_addr.script_pubkey();

    let tx = taproot_spend::build_signed_spend(
        &data,
        auth.into(),
        outpoint,
        Amount::from_sat(prevout_value),
        &to_spk,
        Amount::from_sat(fee),
        net,
    )?;

    // Only the raw tx hex goes to stdout.
    println!("{}", hex::encode(encode::serialize(&tx)));

    let witness_items = tx.input[0].witness.len();
    eprintln!("bip110pack: built reveal tx");
    eprintln!("  auth:            {auth:?}");
    eprintln!("  network:         {net}");
    eprintln!("  txid:            {}", tx.compute_txid());
    eprintln!("  data bytes:      {}", data.len());
    eprintln!("  prevout:         {outpoint}");
    eprintln!("  prevout value:   {prevout_value} sat");
    eprintln!("  fee:             {fee} sat");
    eprintln!("  output value:    {} sat", tx.output[0].value.to_sat());
    eprintln!("  witness items:   {witness_items}");
    eprintln!("  weight:          {} WU", tx.weight().to_wu());
    match bip110::validate(&tx) {
        Ok(()) => eprintln!("  BIP-110 check:   PASS"),
        Err(vs) => {
            for v in &vs {
                eprintln!("  VIOLATION {v}");
            }
            return Err(anyhow!("built tx failed BIP-110 validation"));
        }
    }
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match &cli.command {
        Command::Pack { input, out } => cmd_pack(input, out),
        Command::Verify { txhex } => cmd_verify(txhex),
        Command::Extract { txhex, out } => cmd_extract(txhex, out),
        Command::Commit {
            input,
            data_hex,
            auth,
            network,
        } => cmd_commit(input, data_hex, *auth, *network),
        Command::BuildSpend {
            input,
            data_hex,
            auth,
            network,
            prevout,
            prevout_value,
            fee,
            to,
        } => cmd_build_spend(
            input,
            data_hex,
            *auth,
            *network,
            prevout,
            *prevout_value,
            *fee,
            to,
        ),
    }
}
