import fs from "fs";
import yaml from "js-yaml";

import { main } from "./src/main.js";


const config = yaml.load(fs.readFileSync("./bin/test_config.yaml", "utf8"));

console.log(config.proxies.length);
console.log(main(config, "Test Profile").proxies.length);
