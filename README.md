
Generate htpasswd files with bcrypt passwords.

### Example

```rust
use std::error::Error;
use passivized_htpasswd::errors::HtpasswdError;
use passivized_htpasswd::Htpasswd;

fn setup_credentials() -> Result<(), Box<dyn Error>> {
    let mut credentials = Htpasswd::new();

    credentials.set("John Doe", "Don't hardcode")?;
    credentials.write_to_path("www/.htpasswd")?;

    Ok(())
}
```
