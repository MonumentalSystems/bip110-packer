//! `bip110-packer` CLI — pack a block with BIP-110-compliant arbitrary data and
//! verify transactions against the BIP-110 compliance checklist.

use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use bitcoin::consensus::encode;
use bitcoin::{Address, Amount, Network, OutPoint, Transaction, Txid};
use clap::{Parser, Subcommand, ValueEnum};
use std::str::FromStr;

use bip110_packer::bip110;
use bip110_packer::channels::{self, Channel};
use bip110_packer::framing;
use bip110_packer::packer;
use bip110_packer::taproot_spend;
use bip110_packer::tapscript::{Auth, Violate};

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

/// CLI-facing deliberate BIP-110 violation selector (maps to [`Violate`] plus an
/// output-level flag). `none` keeps existing compliant behavior; the others
/// build a spendable-but-non-compliant reveal for enforcement/gap testing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum ViolateArg {
    /// No violation (default): normal compliant commit/spend.
    None,
    /// C3: a 300-byte push inside the tapleaf.
    Push,
    /// C8: an executing OP_IF/OP_ENDIF in the tapleaf.
    Opif,
    /// C7: an OP_SUCCESS opcode in the tapleaf.
    Opsuccess,
    /// C1: compliant leaf, but an oversize (40-byte) non-OP_RETURN output.
    Output,
}

impl ViolateArg {
    /// The leaf-level violation this selector injects (None for `output`).
    fn to_leaf(self) -> Violate {
        match self {
            ViolateArg::None | ViolateArg::Output => Violate::None,
            ViolateArg::Push => Violate::PushTooBig,
            ViolateArg::Opif => Violate::OpIf,
            ViolateArg::Opsuccess => Violate::OpSuccess,
        }
    }
    /// Whether to append the oversize (C1) output.
    fn oversize_output(self) -> bool {
        matches!(self, ViolateArg::Output)
    }
    /// Whether this is the compliant (no-violation) path.
    fn is_none(self) -> bool {
        matches!(self, ViolateArg::None)
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
    name = "bip110-packer",
    about = "Pack a Bitcoin block with BIP-110-compliant arbitrary data via Taproot tapscripts and six other encoding channels",
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
        /// Data-encoding channel the tx was built with.
        #[arg(long, value_enum, default_value_t = Channel::Tapleaf)]
        channel: Channel,
        /// (Informational) the payload was compressed. Ignored: the framing
        /// header is self-describing, so `unframe` auto-detects compression.
        #[arg(long)]
        compress: bool,
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
        /// Data-encoding channel.
        #[arg(long, value_enum, default_value_t = Channel::Tapleaf)]
        channel: Channel,
        /// Compress the payload with DEFLATE before encoding.
        #[arg(long)]
        compress: bool,
        /// Deliberately inject a BIP-110 violation (enforcement/gap testing).
        #[arg(long, value_enum, default_value_t = ViolateArg::None)]
        violate: ViolateArg,
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
        /// Data-encoding channel.
        #[arg(long, value_enum, default_value_t = Channel::Tapleaf)]
        channel: Channel,
        /// Compress the payload with DEFLATE before encoding.
        #[arg(long)]
        compress: bool,
        /// Deliberately inject a BIP-110 violation (enforcement/gap testing).
        #[arg(long, value_enum, default_value_t = ViolateArg::None)]
        violate: ViolateArg,
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

    eprintln!("bip110-packer: packed {} input byte(s)", data.len());
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

fn cmd_extract(txhex: &str, out: &Option<PathBuf>, channel: Channel, compress: bool) -> Result<()> {
    let raw = hex::decode(txhex.trim()).context("decoding tx hex")?;
    let tx: Transaction = encode::deserialize(&raw).context("deserializing transaction")?;

    // Recover the FRAMED bytes from the channel, then unframe. The framing header
    // is self-describing, so `--compress` is informational only.
    let _ = compress;
    let framed = channels::decode(channel, &tx).context("decoding channel payload")?;
    let data = framing::unframe(&framed).context("unframing recovered payload")?;

    eprintln!(
        "bip110-packer: recovered {} data byte(s) ({} framed) via {channel:?}",
        data.len(),
        framed.len()
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

#[allow(clippy::too_many_arguments)]
fn cmd_commit(
    input: &Option<String>,
    data_hex: &Option<String>,
    auth: AuthArg,
    network: NetworkArg,
    channel: Channel,
    compress: bool,
    violate: ViolateArg,
) -> Result<()> {
    let data = resolve_data(input, data_hex)?;
    let net: Network = network.into();

    // Deliberate BIP-110 violations are a tapleaf-only enforcement demo and use
    // the RAW (unframed) data so `commit` and `build-spend` stay consistent.
    if !violate.is_none() {
        if channel != Channel::Tapleaf {
            return Err(anyhow!(
                "--violate is only supported on the `tapleaf` channel"
            ));
        }
        let addr = taproot_spend::commit_address_violation(&data, violate.to_leaf(), net)?;
        let spk = addr.script_pubkey();
        println!("{addr}");
        println!("{}", hex::encode(spk.as_bytes()));
        eprintln!(
            "bip110-packer: commit address for {} data byte(s)",
            data.len()
        );
        eprintln!("  channel:         {channel:?}");
        eprintln!("  network:         {net}");
        eprintln!("  scriptPubKey:    {} bytes", spk.len());
        eprintln!("  NOTE: deliberately BIP-110-NON-COMPLIANT commit (--violate {violate:?})");
        return Ok(());
    }

    let framed = framing::frame(&data, compress);

    // Tapleaf keeps its `--auth` support by calling the taproot path directly;
    // all other commit/reveal channels dispatch through `channels`.
    let addr_opt = if channel == Channel::Tapleaf {
        Some(taproot_spend::commit_address(&framed, auth.into(), net)?)
    } else {
        channels::commit_address(channel, &framed, net)?
    };

    match addr_opt {
        Some(addr) => {
            let spk = addr.script_pubkey();
            println!("{addr}");
            println!("{}", hex::encode(spk.as_bytes()));
            eprintln!(
                "bip110-packer: commit address for {} data byte(s) ({} framed)",
                data.len(),
                framed.len()
            );
            eprintln!("  channel:         {channel:?}");
            eprintln!("  auth:            {auth:?}");
            eprintln!("  compress:        {compress}");
            eprintln!("  network:         {net}");
            eprintln!("  scriptPubKey:    {} bytes", spk.len());
        }
        None => {
            eprintln!(
                "channel {channel:?} is output-only; it has no commit address. \
                 Use `build-spend --channel …` to emit the data tx directly."
            );
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn cmd_build_spend(
    input: &Option<String>,
    data_hex: &Option<String>,
    auth: AuthArg,
    network: NetworkArg,
    channel: Channel,
    compress: bool,
    prevout: &str,
    prevout_value: u64,
    fee: u64,
    to: &str,
    violate: ViolateArg,
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

    // Deliberate BIP-110 violations are a tapleaf-only enforcement demo and use
    // the RAW (unframed) data so `commit` and `build-spend` stay consistent.
    if !violate.is_none() {
        if channel != Channel::Tapleaf {
            return Err(anyhow!(
                "--violate is only supported on the `tapleaf` channel"
            ));
        }
        // Violating reveals are anyone-can-spend; --auth is ignored.
        let tx = taproot_spend::build_spend_violation(
            &data,
            violate.to_leaf(),
            outpoint,
            Amount::from_sat(prevout_value),
            &to_spk,
            Amount::from_sat(fee),
            net,
            violate.oversize_output(),
        )?;
        println!("{}", hex::encode(encode::serialize(&tx)));
        eprintln!("bip110-packer: built reveal tx (deliberate violation)");
        eprintln!("  channel:         {channel:?}");
        eprintln!("  network:         {net}");
        eprintln!("  txid:            {}", tx.compute_txid());
        eprintln!("  data bytes:      {}", data.len());
        eprintln!("  weight:          {} WU", tx.weight().to_wu());
        match bip110::validate(&tx) {
            Ok(()) => eprintln!("  BIP-110 check:   PASS"),
            Err(vs) => {
                for v in &vs {
                    eprintln!("  VIOLATION {v}");
                }
                // Deliberate violation: still emit the hex and exit 0 so a node
                // can be fed the tx for the gap demo.
                eprintln!(
                    "  NOTE: this tx is deliberately BIP-110-NON-COMPLIANT (--violate {violate:?})"
                );
            }
        }
        return Ok(());
    }

    let framed = framing::frame(&data, compress);

    // Tapleaf keeps its `--auth` support by calling the taproot path directly;
    // every other channel dispatches through `channels::build`.
    let tx = if channel == Channel::Tapleaf {
        taproot_spend::build_signed_spend(
            &framed,
            auth.into(),
            outpoint,
            Amount::from_sat(prevout_value),
            &to_spk,
            Amount::from_sat(fee),
            net,
        )?
    } else {
        channels::build(
            channel,
            &framed,
            outpoint,
            Amount::from_sat(prevout_value),
            &to_spk,
            Amount::from_sat(fee),
            net,
        )?
    };

    // Only the raw tx hex goes to stdout.
    println!("{}", hex::encode(encode::serialize(&tx)));

    let witness_items = tx.input.first().map(|i| i.witness.len()).unwrap_or(0);
    eprintln!("bip110-packer: built data tx");
    eprintln!("  channel:         {channel:?}");
    eprintln!("  auth:            {auth:?}");
    eprintln!("  compress:        {compress}");
    eprintln!("  network:         {net}");
    eprintln!("  txid:            {}", tx.compute_txid());
    eprintln!(
        "  data bytes:      {} ({} framed)",
        data.len(),
        framed.len()
    );
    eprintln!("  prevout:         {outpoint}");
    eprintln!("  prevout value:   {prevout_value} sat");
    eprintln!("  fee:             {fee} sat");
    if let Some(o) = tx.output.first() {
        eprintln!("  output[0] value: {} sat", o.value.to_sat());
    }
    eprintln!("  outputs:         {}", tx.output.len());
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
        Command::Extract {
            txhex,
            out,
            channel,
            compress,
        } => cmd_extract(txhex, out, *channel, *compress),
        Command::Commit {
            input,
            data_hex,
            auth,
            network,
            channel,
            compress,
            violate,
        } => cmd_commit(
            input, data_hex, *auth, *network, *channel, *compress, *violate,
        ),
        Command::BuildSpend {
            input,
            data_hex,
            auth,
            network,
            channel,
            compress,
            prevout,
            prevout_value,
            fee,
            to,
            violate,
        } => cmd_build_spend(
            input,
            data_hex,
            *auth,
            *network,
            *channel,
            *compress,
            prevout,
            *prevout_value,
            *fee,
            to,
            *violate,
        ),
    }
}
