use std::{net::TcpListener, net::TcpStream, io::{self, BufReader, BufRead, Write}, collections::HashMap};

pub struct Server {
    host: String,
    port: u16
}

pub struct CodeResponse {
    pub code: String,
    pub state: String,
}

impl Server {
    pub fn new(host: &str, port: u16) -> Server {
        Server{ host: host.to_string(), port }
    }

    pub fn get_code(&self) -> io::Result<CodeResponse> {
        let listener = TcpListener::bind(format!("{}:{}", self.host, self.port))?;
        let mut conn=listener.incoming().next().unwrap()?;
        
        let params = read_request(&conn)?;
        
        let response_body = "Code received, you can close this tab now.";
        let response = format!("HTTP/1.1 200 OK\r\nContent-Lenght: {}\r\n\r\n{}", response_body.len(), response_body);
        conn.write(response.as_bytes())?;
        conn.flush()?;

        Ok(params)
    }
}

fn read_request(stream: &TcpStream) -> io::Result<CodeResponse>{
    let mut conn = BufReader::new(stream);
    
    let mut request_line = String::new();
    conn.read_line(&mut request_line)?;
    let parameters = extract_parameters_from_path(&request_line)?;
    
    if parameters.get("code").is_none() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, format!("Parameter 'code' not present in request: {}", &request_line)));
    } else if parameters.get("state").is_none() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, format!("Parameter 'state' not present in request: {}", &request_line)));
    }

    Ok(CodeResponse{
        code: parameters["code"].to_string(),
        state: parameters["state"].to_string(),
    })
}

fn extract_parameters_from_path(first_line: &String) -> io::Result<HashMap<String, String>> {
    let splitted_line: Vec<&str> = first_line.split(" ").collect();
    if splitted_line.len() != 3 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, format!("Invalid query line (number of chunk invalid:{}): '{}'", splitted_line.len(), first_line) ));
    }
    let path = splitted_line[1];
    let splitted_path: Vec<&str> = path.split("?").collect();
    if splitted_path.len() != 2 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, format!("Invalid query path (Too much or too few '?' character:{}): '{}'", splitted_path.len(), path) ));        
    }

    let mut parameters: HashMap<String, String> = HashMap::new();
    let parameters_chunk = splitted_path[1];
    for parameter in parameters_chunk.split("&") {
        let key_value: Vec<&str> = parameter.split("=").collect();
        if key_value.len() != 2 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, format!("Invalid parameter in query path(Too much or too few '=' character:{}): '{}'", key_value.len(), path) ));                
        }
        parameters.insert(key_value[0].to_string(), key_value[1].to_string());
    }

    Ok(parameters)
}