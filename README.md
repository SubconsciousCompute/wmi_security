# wmi_security

Query TPM and Encryption state for Windows

## Example:

```rust
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
```

## Output:
```
Ok(
    [
        Win32Tpm {
            is_activated_initial_value: Some(
                true,
            ),
            is_enabled_initial_value: Some(
                true,
            ),
            is_owned_initial_value: Some(
                true,
            ),
            spec_version: Some(
                "2.0, 0, 1.38",
            ),
            manufacturer_version: Some(
                "3.87.0.5",
            ),
            manufacturer_version_info: Some(
                "AMD             ",
            ),
            manufacturer_id: Some(
                1095582720,
            ),
            physical_presence_version_info: Some(
                "1.3",
            ),
        },
    ],
)
Ok(
    [
        Win32EncryptableVolume {
            device_id: Some(
                "\\\\?\\Volume{74c96130-89a0-43c0-a260-aed476f4936c}\\",
            ),
            persistent_volume_id: Some(
                "",
            ),
            drive_letter: Some(
                "C:",
            ),
            protection_status: Some(
                0,
            ),
        },
    ],
)
```