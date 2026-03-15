#![no_main]
use libfuzzer_sys::fuzz_target;
use std::fs;
use std::path::PathBuf;

use aix8::decrypt;

fuzz_target!(|data: &[u8]| {

```
let input = PathBuf::from("fuzz_input.ai");
let output = PathBuf::from("fuzz_output.tmp");

let _ = fs::write(&input, data);

let _ = decrypt(&input, &output, "fuzzpass");
```

});
