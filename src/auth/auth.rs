use garde::Validate;
use reqwest::Client;
use serde::{Serialize, Deserialize};

use crate::local_config::BASE_URL;
use crate::runtime::RUNTIME;

#[derive(uniffi::Record, serde::Deserialize)]
pub struct ResultResponse {
    pub success: bool,
    pub errors: Vec<String>,
}

// 1. Custom Password Rule: Checks min 8 chars, 1 uppercase, 1 digit, 1 special character
fn validate_password(pwd: &str, _context: &()) -> garde::Result {
    if pwd.len() < 8 {
        return Err(garde::Error::new("Password must be at least 8 characters long"));
    }
    if !pwd.chars().any(|c| c.is_uppercase()) {
        return Err(garde::Error::new("Password must contain at least one uppercase letter"));
    }
    if !pwd.chars().any(|c| c.is_numeric()) {
        return Err(garde::Error::new("Password must contain at least one number"));
    }
    if !pwd.chars().any(|c| !c.is_alphanumeric()) {
        return Err(garde::Error::new("Password must contain at least one special character (!@#$%^&*)"));
    }
    Ok(())
}

// 2. Gmail validation
fn validate_gmail(email: &str, _context: &()) -> garde::Result {
    if !email.to_lowercase().ends_with("@gmail.com") {
        return Err(garde::Error::new("Only @gmail.com addresses are allowed"));
    }
    Ok(())
}

// 3. The Validator Struct
#[derive(Validate, Serialize)]
pub struct SignUpValidator<'a> {
    #[garde(length(graphemes, min = 3, max = 64), alphanumeric)]
    pub userid: &'a str,

    #[garde(email, custom(validate_gmail))]
    pub email: &'a str,

    #[garde(custom(validate_password))]
    pub pwd: &'a str,
}

// 4. The UniFFI Exported Function
#[uniffi::export]
pub fn on_sign_up(
    userid: String,
    email: String,
    pwd: String,
) -> ResultResponse {
    let payload = SignUpValidator {
        userid: &userid,
        email: &email,
        pwd: &pwd,
    };

    let check = validate_form(&payload);
    if !check.success {
        println!("{}", check.success);
        return check;
    }
    println!("{:?}", check.errors);
    
     return RUNTIME.block_on(async {
        let client = Client::new();
        let url = format!("{}/signup", BASE_URL);

        match client
            .post(url)
            .json(&payload)
            .send()
            .await {
                Ok(res) => {
                    let backend_reponse = res.json::<ResultResponse>()
                    .await.unwrap_or(ResultResponse { 
                        success: false,
                        errors: vec!["Unexpected return data type".to_string()] 
                    });
                    ResultResponse {
                        success: backend_reponse.success,
                        errors: backend_reponse.errors
                    }
                }

                Err(_) => {
                    ResultResponse {
                        success: false,
                        errors: vec!["Error with Server Response".to_string()]
                    }
                }
            }
     });

}

#[derive(Serialize, Validate)]
pub struct SignInValidator<'a> {
    #[garde(email)]
    pub email: &'a str,
    #[garde(length(graphemes, min = 1))]
    pub pwd: &'a str,
}

#[uniffi::export]
pub fn on_sign_in(
    email: String,
    pwd: String,
) -> ResultResponse {
    let payload = SignInValidator {
        email: &email,
        pwd: &pwd,
    };

    // Form check
    let check = validate_form(&payload);
    if !check.success {
        println!("validation failed");
        return check;
    }

    // Connect to backend API (/signin)
    return RUNTIME.block_on(async {
        let client = Client::new();
        let url = format!("{}/signin", BASE_URL);

        match client.post(url).json(&payload).send().await {
            Ok(res) => {
            let backend_response = res.json::<ResultResponse>()
                .await.unwrap_or(ResultResponse { 
                    success: false,
                    errors: vec!["Unexpected return data type".to_string()] 
                });
                println!("Login is successful");
                ResultResponse {
                    success: backend_response.success,
                    errors: vec![]
                }
            }
            Err(_) => {
            return  ResultResponse {
                    success: false,
                    errors: vec!["Error with Server Response".to_string()]
                };
            }
        }
    });
}


// Reusable standalone function: validates any garde payload
pub fn validate_form<T: garde::Validate<Context = ()>>(payload: &T) -> ResultResponse {
    if let Err(report) = payload.validate() {
        let all_errors: Vec<String> = report
            .iter()
            .map(|(_field, error)| error.to_string())
            .collect();

        ResultResponse {
            success: false,
            errors: all_errors,
        }
    } else {
        ResultResponse {
            success: true,
            errors: vec![],
        }
    }
}