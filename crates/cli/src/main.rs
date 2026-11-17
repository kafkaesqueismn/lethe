use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Parser;
use lethe_client::{Agent, AgentConfig, ChatItem, ContactStatus, Direction, Event, ItemStatus, RelayAddr, StoreLocation};
use tokio::io::{AsyncBufReadExt, BufReader};

/// lethe: private messaging with no accounts and no identifiers.
#[derive(Parser)]
#[command(version)]
struct Args {
    /// Profile directory (holds the encrypted store).
    #[arg(long, default_value = "lethe-profile")]
    profile: PathBuf,
    /// Relay where your receiving queues are created (lethe-relay://...).
    #[arg(long, env = "LETHE_RELAY")]
    relay: Option<RelayAddr>,
    /// SOCKS5 proxy for all connections, e.g. 127.0.0.1:9050 for Tor.
    #[arg(long)]
    proxy: Option<SocketAddr>,
    /// Name to share with new contacts (optional; each contact can get a different one with /invite or /join).
    #[arg(long)]
    name: Option<String>,
    /// Keep nothing on disk.
    #[arg(long)]
    ephemeral: bool,
}

const HELP: &str = "\
commands:
  /invite [alias]          create a one-time invitation link
  /join <link> [alias]     accept an invitation
  /contacts                list contacts
  /open <id>               switch to a chat (plain text is then sent there)
  /msg <id> <text>         send to a specific contact
  /history [n]             show the last n messages of the open chat
  /link <id>               show a pending invitation link again
  /rename <id> <alias>     set a local name for a contact
  /delete <id>             delete a contact (they are told; your queue is removed)
  /quit";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let store = if args.ephemeral {
        StoreLocation::Memory
    } else {
        std::fs::create_dir_all(&args.profile)?;
        let path = args.profile.join("lethe.db");
        let passphrase = match std::env::var("LETHE_PASSPHRASE") {
            Ok(p) => p,
            Err(_) => {
                let p = rpassword::prompt_password(if path.exists() { "passphrase: " } else { "new passphrase: " })?;
                if !path.exists() && rpassword::prompt_password("repeat: ")? != p {
                    anyhow::bail!("passphrases differ");
                }
                p
            }
        };
        StoreLocation::File { path, passphrase }
    };
    let agent = Agent::start(AgentConfig { store, socks_proxy: args.proxy, fast_kdf_for_tests: false }).await?;

    let mut events = agent.subscribe();
    let ev_agent = agent.clone();
    tokio::spawn(async move {
        while let Ok(e) = events.recv().await {
            let name = |id: u64| {
                let a = ev_agent.clone();
                async move { a.contacts().await.into_iter().find(|c| c.id == id).map(|c| c.name).unwrap_or_default() }
            };
            match e {
                Event::ContactConnected { contact_id } => println!("* connected: [{contact_id}] {}", name(contact_id).await),
                Event::Message { contact_id, item } => println!("[{contact_id}] {}: {}", name(contact_id).await, item.text),
                Event::ItemStatus { status: ItemStatus::Failed, contact_id, .. } => println!("! message to [{contact_id}] failed"),
                Event::ContactLeft { contact_id } => println!("* [{contact_id}] {} deleted the conversation", name(contact_id).await),
                Event::RelayDisconnected { relay } => println!("* relay {}:{} disconnected, retrying", relay.host, relay.port),
                Event::Error { contact_id, message } => println!("! {}{message}", contact_id.map(|c| format!("[{c}] ")).unwrap_or_default()),
                _ => {}
            }
        }
    });

    println!("lethe ready. /help for commands.");
    let mut open: Option<u64> = None;
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    while let Some(line) = lines.next_line().await? {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let (cmd, rest) = line.split_once(' ').map_or((line, ""), |(a, b)| (a, b.trim()));
        let res: anyhow::Result<()> = async {
            let relay = || args.relay.clone().ok_or_else(|| anyhow::anyhow!("start with --relay <lethe-relay://...> to create queues"));
            let id = |s: &str| s.parse::<u64>().map_err(|_| anyhow::anyhow!("expected a contact id"));
            match cmd {
                "/help" => println!("{HELP}"),
                "/quit" => std::process::exit(0),
                "/invite" => {
                    let (cid, link) = agent.create_invite(&relay()?, opt(rest), args.name.clone()).await?;
                    println!("invitation for [{cid}] (one-time; share it privately):\n{link}");
                }
                "/join" => {
                    let (link, alias) = rest.split_once(' ').map_or((rest, ""), |(a, b)| (a, b));
                    let cid = agent.accept_invite(link, &relay()?, opt(alias), args.name.clone()).await?;
                    println!("joining [{cid}]...");
                    open = Some(cid);
                }
                "/contacts" | "/c" => {
                    for c in agent.contacts().await {
                        let status = match c.status {
                            ContactStatus::Invited => "invited",
                            ContactStatus::Joining => "joining",
                            ContactStatus::Ready => "ready",
                            ContactStatus::Left => "left",
                        };
                        println!("[{}] {} ({status})", c.id, c.name);
                    }
                }
                "/open" => {
                    let cid = id(rest)?;
                    agent.messages(cid).await?;
                    open = Some(cid);
                    println!("chatting with [{cid}]");
                }
                "/msg" => {
                    let (who, text) = rest.split_once(' ').ok_or_else(|| anyhow::anyhow!("/msg <id> <text>"))?;
                    agent.send_text(id(who)?, text).await?;
                }
                "/history" => {
                    let cid = open.ok_or_else(|| anyhow::anyhow!("no chat open"))?;
                    let n = rest.parse().unwrap_or(20);
                    let items = agent.messages(cid).await?;
                    for it in items.iter().rev().take(n).rev() {
                        print_item(it);
                    }
                }
                "/link" => println!("{}", agent.invite_link(id(rest)?).await?),
                "/rename" => {
                    let (who, alias) = rest.split_once(' ').ok_or_else(|| anyhow::anyhow!("/rename <id> <alias>"))?;
                    agent.rename_contact(id(who)?, opt(alias)).await?;
                }
                "/delete" => {
                    agent.delete_contact(id(rest)?).await?;
                    println!("deleted");
                }
                c if c.starts_with('/') => println!("unknown command; /help"),
                _ => {
                    let cid = open.ok_or_else(|| anyhow::anyhow!("no chat open; /open <id>"))?;
                    agent.send_text(cid, line).await?;
                }
            }
            Ok(())
        }
        .await;
        if let Err(e) = res {
            println!("! {e}");
        }
    }
    agent.shutdown().await;
    Ok(())
}

fn opt(s: &str) -> Option<String> {
    (!s.trim().is_empty()).then(|| s.trim().to_string())
}

fn print_item(it: &ChatItem) {
    let who = if it.direction == Direction::Sent { "you" } else { "them" };
    let mark = match it.status {
        ItemStatus::Pending => " (pending)",
        ItemStatus::Failed => " (failed)",
        _ => "",
    };
    println!("  {who}: {}{mark}", it.text);
}
