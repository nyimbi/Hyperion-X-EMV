# Python Automation Starter Kit

Install the local helper package in a virtual environment and generate a hash inventory for a submission pack:

```sh
python -m pip install -e .
hyperion-tools index --root target/hyperion-submission-pack --out target/hyperion-submission-pack/python_index.json
```

The helper package only indexes and hashes files; Rust tooling remains the source of truth for bundle validation and freeze checks.
