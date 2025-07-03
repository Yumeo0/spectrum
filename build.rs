use std::env;
use std::fs::{self, File};
use std::path::{Path, PathBuf};

use quote::{format_ident, quote};
use serde_json::Value;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn main() {
    if let Err(e) = run() {
        eprintln!("Build failed: {}", e);
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR")?;
    let manifest = PathBuf::from(manifest_dir);
    let proto_dir = manifest.join("proto");
    let out_dir = manifest.join("src/game/proto");
    let message_ids_path = manifest.join("src/game");

    ensure_directories_exist(&out_dir, &message_ids_path)?;

    let proto_files = collect_proto_files(&proto_dir)?;
    generate_protobuf_code(&proto_dir, &proto_files, &out_dir)?;

    let packet_ids = load_packet_ids(&proto_dir)?;
    generate_message_ids_module(&packet_ids, &message_ids_path)?;

    emit_cargo_rerun_directives();

    Ok(())
}

fn ensure_directories_exist(out_dir: &PathBuf, message_ids_path: &PathBuf) -> Result<()> {
    fs::create_dir_all(out_dir)?;
    fs::create_dir_all(message_ids_path)?;
    Ok(())
}

fn collect_proto_files(proto_dir: &Path) -> Result<Vec<PathBuf>> {
    let entries = fs::read_dir(proto_dir)?;
    let proto_files: Vec<PathBuf> = entries
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|e| e.to_str()) == Some("proto"))
        .collect();

    if proto_files.is_empty() {
        return Err("No .proto files found in proto directory".into());
    }

    Ok(proto_files)
}

fn generate_protobuf_code(
    proto_dir: &PathBuf,
    proto_files: &[PathBuf],
    out_dir: &PathBuf,
) -> Result<()> {
    let custom_options = protobuf_codegen::Customize::default().gen_mod_rs(false);

    protobuf_codegen::Codegen::new()
        .pure()
        .customize(custom_options)
        .include(proto_dir)
        .inputs(proto_files)
        .out_dir(out_dir)
        .run()?;

    Ok(())
}

fn load_packet_ids(proto_dir: &Path) -> Result<Vec<(u16, String)>> {
    let json_path = proto_dir.join("packetIds.json");
    let json_file = File::open(&json_path)
        .map_err(|e| format!("Failed to open {}: {}", json_path.display(), e))?;

    let json_value: Value = serde_json::from_reader(json_file)
        .map_err(|e| format!("Invalid JSON in {}: {}", json_path.display(), e))?;

    let json_object = json_value
        .as_object()
        .ok_or("Expected JSON object as root element")?;

    let mut packet_ids: Vec<(u16, String)> = Vec::new();

    for (key, value) in json_object {
        let id = key
            .parse::<u16>()
            .map_err(|e| format!("Invalid packet ID '{}': {}", key, e))?;

        let name = value
            .as_str()
            .ok_or_else(|| format!("Expected string value for packet ID {}", id))?;

        packet_ids.push((id, name.to_string()));
    }

    if packet_ids.is_empty() {
        return Err("No packet IDs found in packetIds.json".into());
    }

    packet_ids.sort_by_key(|(id, _)| *id);
    Ok(packet_ids)
}

fn generate_message_ids_module(
    packet_ids: &[(u16, String)],
    message_ids_path: &Path,
) -> Result<()> {
    let variants = packet_ids.iter().map(|(id, name)| {
        let ident = format_ident!("{}", name);
        quote! {
            #[allow(non_camel_case_types)]
            #ident = #id,
        }
    });

    let output = quote! {
        use num_enum::TryFromPrimitive;
        use strum_macros::{AsRefStr, IntoStaticStr};

        #[repr(u16)]
        #[derive(Debug, Copy, Clone, TryFromPrimitive, AsRefStr, IntoStaticStr)]
        pub enum MessageId {
            #(#variants)*
        }
    };

    let output_path = message_ids_path.join("message.rs");
    fs::write(&output_path, output.to_string())
        .map_err(|e| format!("Failed to write {}: {}", output_path.display(), e))?;

    let _ = std::process::Command::new("rustfmt")
        .arg(&output_path)
        .status();

    Ok(())
}

fn emit_cargo_rerun_directives() {
    println!("cargo:rerun-if-changed=proto/packetIds.json");
    println!("cargo:rerun-if-changed=proto/protos.proto");
}
