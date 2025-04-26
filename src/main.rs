mod crypto;

use std::collections::HashMap;
use std::env::args;
use std::fs;
use std::fs::File;
use std::io::{Error, ErrorKind, Read, stdin, Write, Seek, SeekFrom};
use s3cli_lib::{build_key_info, build_key_parameters, KeyInfo};
use s3cli_lib::azure::build_azure_key_info;
use s3cli_lib::qs3::QKeyInfo;
use crate::crypto::{build_crypto_processor, CryptoProcessor};

struct CommandParameters {
    crypto_processor: Box<dyn CryptoProcessor>,
    max_file_size: u64
}

struct LocalFile {
    file: File,
    num_parts: u64,
    file_size: u64,
    parameters: CommandParameters
}

impl LocalFile {
    fn open(file_name: String, parameters: CommandParameters) -> Result<LocalFile, Error> {
        let file = fs::File::open(file_name)?;
        let file_size = file.metadata()?.len();
        let mut num_parts = file_size / parameters.max_file_size;
        if file_size % parameters.max_file_size != 0 {num_parts += 1}
        Ok(LocalFile{file, num_parts, file_size, parameters})
    }
    
    fn get_part(&mut self, part_number: u64, dest_file_name: &String)
        -> Result<(Vec<u8>, String), Error> {
        let seek_pos = self.parameters.max_file_size * part_number;
        self.file.seek(SeekFrom::Start(seek_pos))?;
        let mut expected_size = self.file_size - seek_pos;
        if expected_size > self.parameters.max_file_size {expected_size = self.parameters.max_file_size}
        let mut buffer = vec![0u8; expected_size as usize];
        let size = self.file.read(&mut buffer)?;
        if size != expected_size as usize {
            return Err(Error::new(ErrorKind::InvalidData, "Corrupted file"));
        }
        let mut file_name = dest_file_name.clone();
        if self.num_parts > 1 {
            file_name += part_number.to_string().as_str();
        }
        let encrypted = self.parameters.crypto_processor.encrypt(buffer)?;
        println!("File part {} size {} file name {}", part_number, encrypted.len(), file_name);
        Ok((encrypted, file_name))
    }
}

fn usage() {
    println!("Usage: s3cli
    [cp source_file_name destination_file_name]
    [ls remote_name:path]
    [url_get remote_name:remote_file]
    [url_put remote_name:remote_file]
    [qcp source_file_name destination_file_name]")
}

fn build_parameters(file_name: &String) -> Result<HashMap<String, String>, Error> {
    let data = load_file(file_name)?;
    build_key_parameters(data)
}

fn build_key_info_from_parameters(file_name: &String, parameters: &HashMap<String, String>)
    -> Result<Box<dyn KeyInfo>, Error> {
    let key_info: Box<dyn KeyInfo> = if file_name.contains("azure") {
        Box::new(build_azure_key_info(parameters)?)
    } else{
        Box::new(build_key_info(parameters)?)
    };
    Ok(key_info)
}

fn build_qkey_info_from_parameters(parameters: &HashMap<String, String>)
    -> Result<Box<dyn KeyInfo>, Error> {
    let config_file_name = parameters.get("config").ok_or(Error::new(ErrorKind::NotFound, "missing config parameter"))?;
    let config = load_file(config_file_name)?;
    let rsa_file_name = parameters.get("rsa_key").ok_or(Error::new(ErrorKind::NotFound, "missing rsa_key parameter"))?;
    let rsa_key = fs::read_to_string(rsa_file_name)?;
    let read_timeout = parameters.get("read_timeout")
        .map(|s| s.parse::<u64>())
        .unwrap_or(Ok(2))
        .map_err(|s| Error::new(ErrorKind::InvalidInput, s))?;
    let retries = parameters.get("retries")
        .map(|s| s.parse::<usize>())
        .unwrap_or(Ok(3))
        .map_err(|s| Error::new(ErrorKind::InvalidInput, s))?;
    let qkey_info = QKeyInfo::new(config, rsa_key, read_timeout, retries)?;
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

fn parse_remote_name(parameter: &String, config: &HashMap<String, String>)
    -> Result<(Box<dyn KeyInfo>, String), Error> {
    let (remote_file, file_name) = parse_file_name(parameter, config)?;
    let remote_file_name = remote_file.ok_or(Error::new(ErrorKind::InvalidData, "missing remote name"))?;
    let parameters = build_parameters(&remote_file_name)?;
    let key_info = build_key_info_from_parameters(&remote_file_name, &parameters)?;
    Ok((key_info, file_name))
}

fn main() -> Result<(), Error> {
    let all_arguments: Vec<String> = args()
        .skip(1)
        .collect();
    let arguments: Vec<String> = all_arguments.iter()
        .filter(|a|!a.starts_with("-"))
        .map(|a| a.clone())
        .collect();
    let options: HashMap<String, String> = all_arguments.iter()
        .filter(|a|a.starts_with("-"))
        .map(|a| a.split_once('=').unwrap_or((a.as_str(), "")))
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect();
    let l = arguments.len();
    if l < 2 || l > 3 {
        usage();
    } else {
        let config = build_key_parameters(fs::read("configuration.ini")?)?;
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
                            let parameters = build_parameters(&remote_file)?;
                            let key_info = build_key_info_from_parameters(&remote_file, &parameters)?;
                            let command_parameters =
                                build_command_parameters(config, parameters, options)?;
                            run_get_command(key_info, &source_file_name, &dest_file_name, command_parameters)?;
                        },
                        None => {
                            match dest_remote_file {
                                Some(remote_file) => {
                                    let parameters = build_parameters(&remote_file)?;
                                    let key_info = build_key_info_from_parameters(&remote_file, &parameters)?;
                                    let command_parameters = build_command_parameters(config, parameters, options)?;
                                    run_put_command(key_info, &source_file_name, &dest_file_name, command_parameters)?;
                                }
                                None => {
                                    let command_parameters = build_command_parameters(config, HashMap::new(), options)?;
                                    run_local_copy(source_file_name, dest_file_name, command_parameters)?
                                }
                            }
                        }
                    }
                }
            },
            "url_get" => {
                if l != 2 {
                    usage()
                } else {
                    let (key_info, file_name) = parse_remote_name(&arguments[1], &config)?;
                    run_get_url_command(key_info, &file_name)?;
                }
            },
            "url_put" => {
                if l != 2 {
                    usage()
                } else {
                    let (key_info, file_name) = parse_remote_name(&arguments[1], &config)?;
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
                            let parameters = build_parameters(&remote_file)?;
                            let key_info = build_qkey_info_from_parameters(&parameters)?;
                            let command_parameters = build_command_parameters(config, parameters, options)?;
                            run_get_command(key_info, &source_file_name, &dest_file_name, command_parameters)?;
                        },
                        None => {
                            match dest_remote_file {
                                Some(remote_file) => {
                                    let parameters = build_parameters(&remote_file)?;
                                    let key_info = build_qkey_info_from_parameters(&parameters)?;
                                    let command_parameters = build_command_parameters(config, parameters, options)?;
                                    run_put_command(key_info, &source_file_name, &dest_file_name, command_parameters)?;
                                }
                                None => {
                                    let command_parameters = build_command_parameters(config, HashMap::new(), options)?;
                                    run_local_copy(source_file_name, dest_file_name, command_parameters)?
                                }
                            }
                        }
                    }
                }
            },
            "ls" => {
                if l != 2 {
                    usage()
                } else {
                    let (key_info, path) = parse_remote_name(&arguments[1], &config)?;
                    run_ls_command(key_info, &path)?;
                }
            },
            _ => usage()
        }
    }
    Ok(())
}

fn build_command_parameters(config: HashMap<String, String>, parameters: HashMap<String, String>,
                            options: HashMap<String, String>)
    -> Result<CommandParameters, Error> {
    let encryption_key = options.get("encryption_key")
        .or(parameters.get("encryption_key"))
        .or(config.get("encryption_key"));
    let crypto_processor = build_crypto_processor(encryption_key)?;
    let max_file_size = options.get("max_file_size")
        .or(parameters.get("max_file_size"))
        .or(config.get("max_file_size"))
        .map(|v| parse_size(v))
        .unwrap_or(Ok(u64::MAX))
        .map_err(|s| Error::new(ErrorKind::InvalidInput, s))?;
    println!("Max file size {}", max_file_size);
    Ok(CommandParameters{crypto_processor, max_file_size})
}

fn parse_size(size_string: &String) -> Result<u64, Error> {
    if size_string.len() < 2 {
        return Err(Error::new(ErrorKind::InvalidData, "invalid size"));
    }
    let (size, multiplier) = match size_string.chars().last().unwrap() {
        'K' => (size_string[..size_string.len() - 2].to_string(), 1024),
        'M' => (size_string[..size_string.len() - 2].to_string(), 1024 * 1024),
        'G' => (size_string[..size_string.len() - 2].to_string(), 1024 * 1024 * 1024),
        _ => (size_string.clone(), 1)
    };
    size.parse::<u64>()
        .map(|v| v * multiplier)
        .map_err(|s| Error::new(ErrorKind::InvalidInput, s))
}

fn run_local_copy(source_file_name: String, dest_file_name: String,
                  parameters: CommandParameters) -> Result<(), Error> {
    let mut file = LocalFile::open(source_file_name, parameters)?;
    for part_no in 0..file.num_parts {
        let (part, file_name) = file.get_part(part_no, &dest_file_name)?;
        let mut f = File::create(file_name)?;
        f.write_all(&part)?;
    }
    Ok(())
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
                    parameters: CommandParameters) -> Result<(), Error> {
    let request_info = key_info.build_request_info("GET",
                                                   chrono::Utc::now(), &Vec::new(),
                                                   remote_file)?;
    let data = request_info.make_request(None)?;
    let decrypted = parameters.crypto_processor.decrypt(data)?;
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
                   parameters: CommandParameters) -> Result<(), Error> {
    let data = load_file(local_file)?;
    let encrypted = parameters.crypto_processor.encrypt(data)?;
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