use std::env::args;
use std::fs::File;
use std::io::{Error, ErrorKind, Read, Write};
use s3cli_lib::{KeyInfo, SourceType};

fn usage() {
    println!("Usage: s3cli key_file [get remote_file local_file][ls path][put local_file remote_file]")
}

fn main() -> Result<(), Error> {
    let arguments: Vec<String> = args().skip(1).collect();
    let l = arguments.len();
    if l < 3 || l > 4 {
        usage();
    } else {
        let key_info = build_key_info(&arguments[0])?;
        match arguments[1].as_str() {
            "get" => {
                if l != 4 {
                    usage()
                } else {
                    run_get_command(key_info, &arguments[2], &arguments[3])?;
                }
            },
            "put" => {
                if l != 4 {
                    usage()
                } else {
                    run_put_command(key_info, &arguments[2], &arguments[3])?;
                }
            },
            "ls" => {
                if l != 3 {
                    usage()
                } else {
                    run_ls_command(key_info, &arguments[2])?;
                }
            },
            _ => usage()
        }
    }
    Ok(())
}

fn load_file(file_name: &String) -> Result<Vec<u8>, Error> {
    let mut f = File::open(file_name)?;
    let mut data = Vec::new();
    f.read_to_end(&mut data)?;
    Ok(data)
}

fn run_get_command(key_info: KeyInfo, remote_file: &String, local_file: &String) -> Result<(), Error> {
    let request_info = key_info.build_request_info("GET",
                                                   chrono::Utc::now(), &Vec::new(),
                                                   remote_file)?;
    let data = request_info.make_request(None)?;
    let mut f = File::create(local_file)?;
    f.write_all(&data)?;
    Ok(())
}

fn run_put_command(key_info: KeyInfo, local_file: &String, remote_file: &String) -> Result<(), Error> {
    let data = load_file(local_file)?;
    let request_info = key_info.build_request_info("PUT",
                                                   chrono::Utc::now(), &data,
                                                   remote_file)?;
    let data = request_info.make_request(Some(data))?;
    let text = String::from_utf8(data)
        .map_err(|e|Error::new(ErrorKind::InvalidData, e.to_string()))?;
    println!("{}", text);
    Ok(())
}

fn run_ls_command(key_info: KeyInfo, path: &String) -> Result<(), Error> {
    let request_info = key_info.build_request_info("GET",
                                                   chrono::Utc::now(),
                                                   &Vec::new(), path)?;
    let data = request_info.make_request(None)?;
    let text = String::from_utf8(data)
        .map_err(|e|Error::new(ErrorKind::InvalidData, e.to_string()))?;
    println!("{}", text);
    Ok(())
}

fn build_key_info(file_name: &String) -> Result<KeyInfo, Error> {
    let data = load_file(file_name)?;
    let text = String::from_utf8(data)
        .map_err(|e|Error::new(ErrorKind::InvalidData, e.to_string()))?;
    let lines: Vec<String> = text.split('\n')
        .map(|v|v.to_string().trim().to_string())
        .collect();
    if lines.len() < 4 || lines[0].is_empty() || lines[1].is_empty() || lines[2].is_empty() ||
        lines[3].is_empty() {
        return Err(Error::new(ErrorKind::InvalidData, "incorrect key file"));
    }
    let source_type = match lines[0].as_str() {
        "aws" => SourceType::AWS,
        "gcp" => SourceType::GCP,
        _ => return Err(Error::new(ErrorKind::InvalidData, "unknown source type"))
    };
    Ok(KeyInfo::new(
        source_type,
        lines[1].clone(),
        lines[2].clone(),
        lines[3].clone(),
    ))
}