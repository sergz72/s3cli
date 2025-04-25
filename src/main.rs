mod crypto;

use std::collections::HashMap;
use std::env::args;
use std::fs;
use std::fs::File;
use std::io::{Error, ErrorKind, Read, stdin, Write};
use s3cli_lib::{build_key_info, build_key_parameters, KeyInfo};
use s3cli_lib::azure::build_azure_key_info;
use s3cli_lib::qs3::QKeyInfo;
use crate::crypto::{build_crypto_processor, CryptoProcessor};

fn usage() {
    println!("Usage: s3cli
    [cp source_file_name destination_file_name]
    [ls remote_name:path]
    [url_get remote_name:remote_file]
    [url_put remote_name:remote_file]
    [qcp source_file_name destination_file_name]")
}

fn build_key_info_from_file(file_name: &String) -> Result<Box<dyn KeyInfo>, Error> {
    let data = load_file(file_name)?;
    let parameters = build_key_parameters(data)?;
    let key_info: Box<dyn KeyInfo> = if file_name.contains("azure") {
        Box::new(build_azure_key_info(&parameters)?)
    } else{
        Box::new(build_key_info(&parameters)?)
    };
    Ok(key_info)
}

fn build_qkey_info_from_file(file_name: &String) -> Result<Box<dyn KeyInfo>, Error> {
    let text = fs::read_to_string(file_name)?;
    let lines: Vec<String> = text
        .split('\n')
        .map(|v| v.to_string().trim().to_string())
        .collect();
    if lines.len() < 2 {
        return Err(Error::new(ErrorKind::InvalidData, "incorrect qkey file"));
    }
    let config = load_file(&lines[0])?;
    let rsa_key = fs::read_to_string(&lines[1])?;
    let qkey_info = QKeyInfo::new(config, rsa_key, 2, 3)?;
    Ok(Box::new(qkey_info))
}

fn parse_file_name(file_name: &String, config: &HashMap<String, String>)
    -> Result<(Option<String>, String), Error> {
    match file_name.split_once(':') {
        Some((remote_name, file_name)) => {
            let remote_file = config.get(remote_name)
                .ok_or(Error::new(ErrorKind::InvalidData, "unknown remote name"))?;
            Ok((Some(remote_file.clone()), file_name.to_string()))
        },
        None => Ok((None, file_name.clone()))
    }
}

fn main() -> Result<(), Error> {
    let arguments: Vec<String> = args().skip(1).collect();
    let l = arguments.len();
    if l < 2 || l > 3 {
        usage();
    } else {
        let config = build_key_parameters(fs::read("configuration.ini")?)?;
        let crypto_processor = build_crypto_processor(config.get("encryption_key"))?;
        match arguments[0].as_str() {
            "cp" => {
                if l != 3 {
                    usage()
                } else {
                    let (source_remote_file, source_file_name) = parse_file_name(&arguments[1], &config)?;
                    let (dest_remote_file, dest_file_name) = parse_file_name(&arguments[2], &config)?;
                    if source_remote_file.is_some() && dest_remote_file.is_some() {
                        return Err(Error::new(ErrorKind::InvalidData, "copy remote to remote is not supported"));
                    }
                    match source_remote_file {
                        Some(remote_file) => {
                            let key_info = build_key_info_from_file(&remote_file)?;
                            run_get_command(key_info, &source_file_name, &dest_file_name, crypto_processor)?;
                        },
                        None => {
                            match dest_remote_file {
                                Some(remote_file) => {
                                    let key_info = build_key_info_from_file(&remote_file)?;
                                    run_put_command(key_info, &source_file_name, &dest_file_name, crypto_processor)?;
                                }
                                None => run_local_copy(source_file_name, dest_file_name, crypto_processor)?
                            }
                        }
                    }
                }
            },
            "url_get" => {
                if l != 2 {
                    usage()
                } else {
                    let (remote_file, file_name) = parse_file_name(&arguments[1], &config)?;
                    let remote_file_name = remote_file.ok_or(Error::new(ErrorKind::InvalidData, "missing remote name"))?;
                    let key_info = build_key_info_from_file(&remote_file_name)?;
                    run_get_url_command(key_info, &file_name)?;
                }
            },
            "url_put" => {
                if l != 2 {
                    usage()
                } else {
                    let (remote_file, file_name) = parse_file_name(&arguments[1], &config)?;
                    let remote_file_name = remote_file.ok_or(Error::new(ErrorKind::InvalidData, "missing remote name"))?;
                    let key_info = build_key_info_from_file(&remote_file_name)?;
                    run_put_url_command(key_info, &file_name)?;
                }
            },
            "qcp" => {
                if l != 3 {
                    usage()
                } else {
                    let (source_remote_file, source_file_name) = parse_file_name(&arguments[1], &config)?;
                    let (dest_remote_file, dest_file_name) = parse_file_name(&arguments[2], &config)?;
                    if source_remote_file.is_some() && dest_remote_file.is_some() {
                        return Err(Error::new(ErrorKind::InvalidData, "qcopy remote to remote is not supported"));
                    }
                    match source_remote_file {
                        Some(remote_file) => {
                            let key_info = build_qkey_info_from_file(&remote_file)?;
                            run_get_command(key_info, &source_file_name, &dest_file_name, crypto_processor)?;
                        },
                        None => {
                            match dest_remote_file {
                                Some(remote_file) => {
                                    let key_info = build_qkey_info_from_file(&remote_file)?;
                                    run_put_command(key_info, &source_file_name, &dest_file_name, crypto_processor)?;
                                }
                                None => run_local_copy(source_file_name, dest_file_name, crypto_processor)?
                            }
                        }
                    }
                }
            },
            "ls" => {
                if l != 2 {
                    usage()
                } else {
                    let (remote_file, path) = parse_file_name(&arguments[1], &config)?;
                    let remote_file_name = remote_file.ok_or(Error::new(ErrorKind::InvalidData, "missing remote name"))?;
                    let key_info = build_key_info_from_file(&remote_file_name)?;
                    run_ls_command(key_info, &path)?;
                }
            },
            _ => usage()
        }
    }
    Ok(())
}

fn run_local_copy(source_file_name: String, dest_file_name: String,
                  crypto_processor: Box<dyn CryptoProcessor>) -> Result<(), Error> {
    let data = load_file(&source_file_name)?;
    let encrypted = crypto_processor.encrypt(data)?;
    let mut f = File::create(dest_file_name)?;
    f.write_all(&encrypted)
}

fn load_file(file_name: &String) -> Result<Vec<u8>, Error> {
    let mut data = Vec::new();
    if file_name.starts_with("-") {
        stdin().read_to_end(&mut data)?;
    } else {
        let mut f = File::open(file_name)?;
        f.read_to_end(&mut data)?;
    }
    Ok(data)
}

fn run_get_command(key_info: Box<dyn KeyInfo>, remote_file: &String, local_file: &String,
                    crypto_processor: Box<dyn CryptoProcessor>) -> Result<(), Error> {
    let request_info = key_info.build_request_info("GET",
                                                   chrono::Utc::now(), &Vec::new(),
                                                   remote_file)?;
    let data = request_info.make_request(None)?;
    let decrypted = crypto_processor.decrypt(data)?;
    let mut f = File::create(local_file)?;
    f.write_all(&decrypted)
}

fn run_get_url_command(key_info: Box<dyn KeyInfo>, remote_file: &String) -> Result<(), Error> {
    let url = key_info.build_presigned_url("GET",
                                                   chrono::Utc::now(), remote_file,
                                                   60)?;
    println!("{}", url);
    Ok(())
}

fn run_put_url_command(key_info: Box<dyn KeyInfo>, remote_file: &String) -> Result<(), Error> {
    let url = key_info.build_presigned_url("PUT",
                                           chrono::Utc::now(), remote_file,
                                           60)?;
    println!("{}", url);
    Ok(())
}

fn run_put_command(key_info: Box<dyn KeyInfo>, local_file: &String, remote_file: &String,
                   crypto_processor: Box<dyn CryptoProcessor>) -> Result<(), Error> {
    let data = load_file(local_file)?;
    let encrypted = crypto_processor.encrypt(data)?;
    let request_info = key_info.build_request_info("PUT",
                                                   chrono::Utc::now(), &encrypted,
                                                   remote_file)?;
    let data = request_info.make_request(Some(encrypted))?;
    let text = String::from_utf8(data)
        .map_err(|e|Error::new(ErrorKind::InvalidData, e.to_string()))?;
    println!("{}", text);
    Ok(())
}

fn run_ls_command(key_info: Box<dyn KeyInfo>, path: &String) -> Result<(), Error> {
    let request_info = key_info.build_request_info("GET",
                                                   chrono::Utc::now(),
                                                   &Vec::new(), path)?;
    let data = request_info.make_request(None)?;
    let text = String::from_utf8(data)
        .map_err(|e|Error::new(ErrorKind::InvalidData, e.to_string()))?;
    println!("{}", text);
    Ok(())
}