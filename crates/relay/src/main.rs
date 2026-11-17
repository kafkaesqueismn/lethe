use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;

/// lethe relay: hosts anonymous one-way message queues. No accounts, no logs of who talks to whom.
#[derive(Parser)]
#[command(version)]
struct Args {
    /// Address to listen on.
    #[arg(long, default_value = "0.0.0.0:5223")]
    listen: SocketAddr,
    /// Public hostname, IP or .onion address clients will use to reach this relay.
    #[arg(long, default_value = "localhost")]
    host: String,
    /// Directory for the relay's TLS identity (its fingerprint is part of the address).
    #[arg(long, default_value = "relay-data")]
    data_dir: PathBuf,
    /// Hours to keep undelivered messages.
    #[arg(long, default_value_t = 21 * 24)]
    ttl_hours: u64,
    /// Maximum undelivered messages per queue.
    #[arg(long, default_value_t = 256)]
    max_queue_messages: usize,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::from_default_env()).init();
    let args = Args::parse();
    let relay = lethe_relay::start(lethe_relay::Config {
        listen: args.listen,
        public_host: args.host,
        data_dir: Some(args.data_dir),
        message_ttl: Duration::from_secs(args.ttl_hours * 3600),
        max_queue_messages: args.max_queue_messages,
        ..Default::default()
    })
    .await?;
    println!("lethe relay listening on {}", relay.local_addr);
    println!("relay address (share this with clients):\n  {}", relay.addr);
    tokio::signal::ctrl_c().await?;
    relay.shutdown();
    Ok(())
}
