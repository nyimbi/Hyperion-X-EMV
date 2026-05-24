use hyperion_emv::ffi::{
    krn_get_callback_timeout_policy, KrnCallbackTimeoutPolicy, KRN_ABI_VERSION,
};
use hyperion_emv::KernelError;
use std::mem;
use std::process;

fn main() {
    match read_timeout_policy() {
        Ok(policy) => println!("{}", policy_to_json(&policy)),
        Err(err) => {
            eprintln!("failed to read callback timeout policy: {err}");
            process::exit(1);
        }
    }
}

fn read_timeout_policy() -> Result<KrnCallbackTimeoutPolicy, String> {
    let mut policy = KrnCallbackTimeoutPolicy {
        abi_version: KRN_ABI_VERSION,
        struct_size: mem::size_of::<KrnCallbackTimeoutPolicy>() as u32,
        min_timeout_ms: 0,
        max_timeout_ms: 0,
        apdu_transport_timeout_ms: 0,
        host_authorization_timeout_ms: 0,
        pin_entry_timeout_ms: 0,
        contactless_ui_timeout_ms: 0,
    };
    let status = unsafe { krn_get_callback_timeout_policy(&mut policy) };
    if status == KernelError::Ok.code() {
        Ok(policy)
    } else {
        Err(format!("krn_get_callback_timeout_policy returned {status}"))
    }
}

fn policy_to_json(policy: &KrnCallbackTimeoutPolicy) -> String {
    format!(
        "{{\"type\":\"callback-timeout-policy\",\"abi_version\":{},\"min_timeout_ms\":{},\"max_timeout_ms\":{},\"apdu_transport_timeout_ms\":{},\"host_authorization_timeout_ms\":{},\"pin_entry_timeout_ms\":{},\"contactless_ui_timeout_ms\":{}}}",
        policy.abi_version,
        policy.min_timeout_ms,
        policy.max_timeout_ms,
        policy.apdu_transport_timeout_ms,
        policy.host_authorization_timeout_ms,
        policy.pin_entry_timeout_ms,
        policy.contactless_ui_timeout_ms
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emits_callback_timeout_policy_json() {
        let policy = read_timeout_policy().unwrap();
        assert!(policy.apdu_transport_timeout_ms > 0);
        assert!(policy.host_authorization_timeout_ms > 0);
        assert!(policy.pin_entry_timeout_ms > 0);
        assert!(policy.contactless_ui_timeout_ms > 0);

        let json = policy_to_json(&policy);
        assert!(json.contains("\"type\":\"callback-timeout-policy\""));
        assert!(json.contains("\"apdu_transport_timeout_ms\":"));
        assert!(json.contains("\"contactless_ui_timeout_ms\":"));
    }
}
