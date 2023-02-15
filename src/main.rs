use wmi_security::COMLibrary;
use wmi_security::{get_encryption_volume_state, get_tpm_state};

fn main() {
    let com_con = COMLibrary::new().unwrap();

    println!(
        "{:#?}\n{:#?}",
        get_tpm_state(com_con),
        get_encryption_volume_state(com_con)
    );
}
