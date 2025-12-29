const host = "www.netflix.com";
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

const hashHandlers = [
  {
    type: "trojan",
    calculate: (proxy) => [
      proxy.server,
      proxy.port,
      proxy.password,
      proxy.udp && "udp",
      proxy.network || "tcp"
    ].filter(Boolean).join(" + ")
  },
  {
    type: "vless",
    calculate: (proxy) => [
      proxy.server,
      proxy.port,
      proxy.udp && "udp",
      proxy.uuid,
      proxy.network || "tcp"
    ].filter(Boolean).join(" + ")
  },
  {
    type: "vmess",
    calculate: (proxy) => [
      proxy.server,
      proxy.port,
      proxy.udp && "udp",
      proxy.uuid,
      proxy.network || "tcp"
    ].filter(Boolean).join(" + ")
  },
  {
    type: "hysteria2",
    calculate: (proxy) => [
      proxy.server,
      proxy.port,
      proxy.password && `password=${proxy.password}`,
      proxy.tls && "tls",
      proxy.obfs && `obfs=${proxy.obfs}`,
      proxy['obfs-password'] && `obfs-password=${proxy['obfs-password']}`
    ].filter(Boolean).join(" + ")
  }];

function filterProxies(proxies, profileName) {
  if (profileName.includes("Mahdibland")) {
    const countries = ["CN", "🇷🇺RU", "🇳🇱NL", "🏁RELAY", "KR", "🇯🇵JP", "🇲🇾MY", "🇻🇳VN", "🇵🇭PH"];
    proxies = proxies.filter(proxy => !countries.some(item => proxy.name.includes(item)));
  }

  proxies = proxies
    .filter((proxy) => !proxy.name.includes("HK"))
    .filter((proxy) => !unwantedProxyTypes.includes(proxy.type))
    .filter((proxy) => proxy.type !== "vmess" || (proxy.type === "vmess" && proxy.uuid && proxy.uuid.length == 36))
    .filter((proxy) => !isNaN(proxy.port))
    .filter((proxy) => typeof proxy["skip-cert-verify"] !== "undefined" && proxy["skip-cert-verify"])
    .filter(
      (proxy) =>
        !((proxy.type === "vless" || proxy.type === "vmess") && !proxy.tls)
    )
    .map(proxy => {
      proxy.hash = null;
      const hashableTypes = hashHandlers.map(handler => handler.type);
      hashableTypes.includes(proxy.type);
      if (hashableTypes.includes(proxy.type)) {
        const handler = hashHandlers.find(handler => handler.type === proxy.type);
        proxy.hash = handler.calculate(proxy);
      }
      return proxy;
    });
  // .apply hash handlers

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
