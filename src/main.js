// define your host
const host
// const host = "www.netflix.com";
// const host = "zoom.us";

const removeSSProxies = true;
const removeSSRProxies = true;
const removeShadowsocksProxies = true;

const defaultGroupName = "DEFAULT";

const rules = [
  "DOMAIN-SUFFIX,identitytoolkit.googleapis.com,DIRECT",
  `MATCH,${defaultGroupName}`
];

let unwantedProxyTypes = [];
function buildExcludeProxyTypeArray() {
  const excludeTypes = [];
  if (typeof removeSSProxies !== "undefined") excludeTypes.push("ss");
  if (typeof removeSSRProxies !== "undefined") excludeTypes.push("ssr");
  if (typeof removeShadowsocksProxies !== "undefined") excludeTypes.push("shadowsocks");
  return excludeTypes;
}

const buildHash = (...parts) =>
  parts.filter(v => v !== undefined && v !== null).join(" + ");

const proxySettings = [
  {
    type: "general",
    filterConditions: (proxy) =>
      typeof proxy.name === "string" &&
      !proxy.name.includes("HK") &&
      !unwantedProxyTypes.includes(proxy.type) &&
      Number.isInteger(proxy.port) &&
      proxy["skip-cert-verify"] === true
  },
  {
    type: "trojan",
    calculateHash: (proxy) => buildHash(
      proxy.server,
      proxy.port,
      proxy.password,
      proxy.udp && "udp",
      proxy.network || "tcp"
    )
  },
  {
    type: "vless",
    filterConditions: (proxy) => proxy.tls,
    calculateHash: (proxy) => buildHash(
      proxy.server,
      proxy.port,
      proxy.udp && "udp",
      proxy.uuid,
      proxy.network || "tcp"
    )
  },
  {
    type: "vmess",
    filterConditions: (proxy) =>
      proxy.uuid && proxy.uuid.length === 36 &&
      proxy.tls,
    calculateHash: (proxy) => buildHash(
      proxy.server,
      proxy.port,
      proxy.udp && "udp",
      proxy.uuid,
      proxy.network || "tcp"
    )
  },
  {
    type: "hysteria2",
    calculateHash: (proxy) => buildHash(
      proxy.server,
      proxy.port,
      proxy.password && `password=${proxy.password}`,
      proxy.tls && "tls",
      proxy.obfs && `obfs=${proxy.obfs}`,
      proxy['obfs-password'] && `obfs-password=${proxy['obfs-password']}`
    )
  }];

function filterProxies(proxies, profileName) {
  if (profileName.includes("Mahdibland")) {
    const countries = ["CN", "🇷🇺RU", "🇳🇱NL", "🏁RELAY", "KR", "🇯🇵JP", "🇲🇾MY", "🇻🇳VN", "🇵🇭PH"];
    proxies = proxies.filter(proxy => !countries.some(item => proxy.name.includes(item)));
  }

  proxies = proxies.filter(proxy => {
    const generalConditionCheck = proxySettings.find(cond => cond.type === "general").filterConditions(proxy);
    let typeSpecificConditionCheck = false;

    const typeSpecificConditions = proxySettings.filter(settings => settings.type.includes(proxy.type) && settings.filterConditions);

    if (typeSpecificConditions)
      typeSpecificConditionCheck = typeSpecificConditions.every((setting) => setting.filterConditions(proxy));
    else typeSpecificConditionCheck = true;

    return generalConditionCheck && typeSpecificConditionCheck;
  }).map(proxy => {
    // .apply hash handlers
    proxy.hash = null;
    const hashableTypes = proxySettings.map(handler => handler.type);
    hashableTypes.includes(proxy.type);
    if (hashableTypes.includes(proxy.type)) {
      const handler = proxySettings.find(handler => handler.type === proxy.type);
      proxy.hash = handler.calculateHash(proxy);
    }
    return proxy;
  });

  const uniqueProxies = [];
  const hashSet = new Set();

  for (const proxy of proxies) {
    if (proxy.hash) {
      if (!hashSet.has(proxy.hash)) {
        hashSet.add(proxy.hash);
        delete proxy.hash;
        uniqueProxies.push(proxy);
      }
    } else uniqueProxies.push(proxy);
  }

  return uniqueProxies;

}

function updateProxy(proxy, i) {
  if (!proxy.name) proxy.name = `${proxy.server} - ${i}`;

  if (proxy.type == "trojan" || proxy.type == "hysteria" || proxy.type == "hysteria2" || proxy.type == "http") proxy.sni = host;
  if (proxy.type == "vmess" || proxy.type == "vless") proxy.servername = host;


  if (proxy["h2-opts"]) proxy["h2-opts"] = {
    host: [host]
  };


  if (proxy["ws-opts"]) proxy["ws-opts"]["headers"] = {
    Host: host,
  };

  if (proxy["ws-path"]) proxy["ws-opts"] = {
    path: proxy["ws-path"],
    headers: { Host: host, }
  };

  return proxy;
}

export function main(config, profileName) {
  unwantedProxyTypes = buildExcludeProxyTypeArray();
  const filteredProxies = filterProxies(config.proxies, profileName).map(updateProxy);


  config.proxies = filteredProxies;
  config["proxy-groups"] = [
    {
      name: defaultGroupName,
      type: "select",
      proxies: filteredProxies.map(p => p.name)
    }
  ];
  config.rules = rules;


  return config;
}
