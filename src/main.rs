#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    otium_flow::app::run(std::env::args().any(|a| a == "--mobile"))
}
