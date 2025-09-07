use rssh_core::config::Config;
use std::fs;

fn main() {
    let config_json = fs::read_to_string("/home/zero/.rssh-agent/config.json").unwrap();
    println!("Config JSON length: {}", config_json.len());
    println!(
        "First 100 chars: {:?}",
        &config_json[..100.min(config_json.len())]
    );

    match serde_json::from_str::<Config>(&config_json) {
        Ok(config) => println!("Config parsed successfully: {:?}", config.version),
        Err(e) => println!("Failed to parse config: {}", e),
    }
}
