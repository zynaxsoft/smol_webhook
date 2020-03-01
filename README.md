# Smol webhook [(crates.io)](https://crates.io/crates/smol_webhook)

A small rust project that is based on the webserver project in the [rust book](https://doc.rust-lang.org/book/ch20-00-final-project-a-web-server.html).

This script will listen to the github webhook for a push event. It will check branch and it will execute a script placed near the executable.


## Configuration

This application could be configured by using environment variables.

* `SMOL_WEBHOOK_IP` `ip_addr` - IPv4 to listen. default=127.0.0.1
* `SMOL_WEBHOOK_PORT` `port_number` - port to listen. default=7878
* `SMOL_WEBHOOK_BRANCH` `branch_name` - a branch name that this webhook will watch on. default=master
* `SMOL_WEBHOOK_SCRIPT` `script_path` - path of the executable script. default=./test.sh
* `SMOL_WEBHOOK_KEY` `secret_key` - secret key to check in the webhook event. default=""(empty string)
