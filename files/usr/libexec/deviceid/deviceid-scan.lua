#!/usr/bin/lua

local jsonc = require "luci.jsonc"

local VERSION = "0.1.0"

local devices = {}
local by_mac = {}
local by_ip = {}
local by_hostname = {}
local sources = {}
local loaded_rule_files = {}
local loaded_oui_files = {}
local network_interfaces = {}
local online_vendor_cache = {}
local online_vendor_cache_dirty = false
local online_vendor_cache_path = nil
local online_vendor_stats = {
	enabled = false,
	attempted = 0,
	found = 0,
	cache_hits = 0,
	checked = 0,
	remaining = 0,
	skipped = 0,
	errors = 0
}

local function trim(value)
	if value == nil then
		return nil
	end

	value = tostring(value):gsub("^%s+", ""):gsub("%s+$", "")
	if value == "" or value == "*" or value == "?" then
		return nil
	end

	return value
end

local function run(cmd)
	local pipe = io.popen(cmd .. " 2>/dev/null")
	if not pipe then
		return ""
	end

	local data = pipe:read("*a") or ""
	pipe:close()
	return data
end

local function readfile(path)
	local fp = io.open(path, "r")
	if not fp then
		return nil
	end

	local data = fp:read("*a")
	fp:close()
	return data
end

local function file_exists(path)
	local fp = io.open(path, "r")
	if not fp then
		return false
	end

	fp:close()
	return true
end

local function json_decode(data)
	if not data or data == "" then
		return nil
	end

	local ok, parsed = pcall(jsonc.parse, data)
	if ok and type(parsed) == "table" then
		return parsed
	end

	return nil
end

local function json_encode(data)
	local ok, encoded = pcall(jsonc.stringify, data)
	if ok and encoded then
		return encoded
	end

	return "{}"
end

local function shell_quote(value)
	return "'" .. tostring(value):gsub("'", "'\\''") .. "'"
end

local function uci_get(key, fallback)
	local value = trim(run("uci -q get " .. key))
	if value == nil then
		return fallback
	end
	return value
end

local function enabled(key, fallback)
	local value = uci_get(key, fallback)
	return value == "1" or value == "true" or value == "yes" or value == "on"
end

local function value_enabled(value, fallback)
	value = trim(value)
	if value == nil then
		return fallback
	end

	value = value:lower()
	return value == "1" or value == "true" or value == "yes" or value == "on"
end

local function normalize_mac(mac)
	if not mac then
		return nil
	end

	local hex = tostring(mac):upper():gsub("[^0-9A-F]", "")
	if #hex ~= 12 or hex == "000000000000" or hex == "FFFFFFFFFFFF" then
		return nil
	end

	return table.concat({
		hex:sub(1, 2), hex:sub(3, 4), hex:sub(5, 6),
		hex:sub(7, 8), hex:sub(9, 10), hex:sub(11, 12)
	}, ":")
end

local function normalize_oui(value)
	if not value then
		return nil
	end

	local hex = tostring(value):upper():gsub("[^0-9A-F]", "")
	if #hex < 6 then
		return nil
	end

	return hex:sub(1, 6)
end

local function normalize_mac_key(mac)
	local norm = normalize_mac(mac)
	if not norm then
		return nil
	end

	return norm:gsub(":", "")
end

local function is_universal_unicast(mac)
	local key = normalize_mac_key(mac)
	if not key then
		return false
	end

	local first = tonumber(key:sub(1, 2), 16)
	if not first then
		return false
	end

	local multicast = (first % 2) == 1
	local local_admin = (math.floor(first / 2) % 2) == 1
	return not multicast and not local_admin
end

local function uci_unquote(value)
	value = trim(value)
	if not value then
		return nil
	end

	if value:sub(1, 1) == "'" and value:sub(-1) == "'" then
		value = value:sub(2, -2):gsub("'\\''", "'")
	end

	return value
end

local function safe_uci_section(section)
	section = trim(section)
	if not section then
		return nil
	end

	if section:match("^@block%[%d+%]$") or section:match("^[%w_%-]+$") then
		return section
	end

	return nil
end

local function load_block_sections()
	local sections = {}
	local order = {}
	local data = run("uci -q show deviceid")

	for line in data:gmatch("[^\r\n]+") do
		local section, stype = line:match("^deviceid%.([^=]+)=(.*)$")
		if section and stype == "block" then
			sections[section] = sections[section] or { section = section }
			sections[section].type = stype
			order[#order + 1] = section
		end

		local option_section, option, value = line:match("^deviceid%.([^%.=]+)%.([^=]+)=(.*)$")
		if option_section and option and value then
			sections[option_section] = sections[option_section] or { section = option_section }
			sections[option_section][option] = uci_unquote(value)
		end
	end

	return sections, order
end

local function load_blocked_map()
	local sections, order = load_block_sections()
	local map = {}
	local list = {}

	for _, key in ipairs(order) do
		local section = sections[key]
		local mac = section and normalize_mac(section.mac)
		if mac and value_enabled(section.enabled, true) then
			map[mac] = section
			section.mac = mac
			list[#list + 1] = section
		end
	end

	return map, list
end

local function find_block_section(mac)
	local sections, order = load_block_sections()
	mac = normalize_mac(mac)

	if not mac then
		return nil
	end

	for _, key in ipairs(order) do
		local section = sections[key]
		if normalize_mac(section and section.mac) == mac then
			return key, section
		end
	end

	return nil
end

local function uci_set_option(section, option, value)
	section = safe_uci_section(section)
	if not section or not option:match("^[%w_%-]+$") then
		return false
	end

	os.execute("uci -q set " .. shell_quote("deviceid." .. section .. "." .. option .. "=" .. tostring(value)))
	return true
end

local function command_path(name, fallback)
	return trim(run("command -v " .. name)) or fallback or name
end

local function add_unique(list, value)
	value = trim(value)
	if not value then
		return false
	end

	for _, item in ipairs(list) do
		if item == value then
			return false
		end
	end

	list[#list + 1] = value
	return true
end

local function is_ipv6(ip)
	return ip and ip:find(":", 1, true) ~= nil
end

local function new_device()
	local dev = {
		ipv4 = {},
		ipv6 = {},
		hostnames = {},
		interfaces = {},
		services = {},
		service_details = {},
		sources = {},
		facts = {},
		online = false,
		blocked = false
	}

	devices[#devices + 1] = dev
	return dev
end

local function add_fact(dev, source, detail)
	if not dev or not detail then
		return
	end

	dev.facts[#dev.facts + 1] = {
		source = source or "unknown",
		detail = tostring(detail)
	}
end

local function add_source(dev, source)
	if not dev or not source then
		return
	end

	dev.sources[source] = true
	sources[source] = true
end

local function add_ip(dev, ip)
	ip = trim(ip)
	if not ip then
		return
	end

	local list = is_ipv6(ip) and dev.ipv6 or dev.ipv4
	if add_unique(list, ip) then
		by_ip[ip] = dev
	end
end

local function add_hostname(dev, hostname)
	hostname = trim(hostname)
	if not hostname then
		return
	end

	if add_unique(dev.hostnames, hostname) then
		by_hostname[hostname:lower()] = dev
	end
end

local function add_interface(dev, ifname)
	if add_unique(dev.interfaces, ifname) then
		return true
	end
	return false
end

local function add_service(dev, service, detail)
	if not dev then
		return
	end

	if add_unique(dev.services, service) then
		add_fact(dev, "service", service)
	end

	detail = trim(detail)
	if detail then
		add_unique(dev.service_details, detail)
	end
end

local function ensure_device(mac, ip, hostname)
	mac = normalize_mac(mac)
	ip = trim(ip)
	hostname = trim(hostname)

	local dev = nil
	if mac then
		dev = by_mac[mac]
	end

	if not dev and ip then
		dev = by_ip[ip]
	end

	if not dev and hostname then
		dev = by_hostname[hostname:lower()]
	end

	if not dev then
		dev = new_device()
	end

	if mac and not dev.mac then
		dev.mac = mac
		by_mac[mac] = dev
	elseif mac then
		by_mac[mac] = dev
	end

	if ip then
		add_ip(dev, ip)
	end

	if hostname then
		add_hostname(dev, hostname)
	end

	return dev
end

local function ubus_call(object, method, params)
	local cmd = "ubus -S call " .. shell_quote(object) .. " " .. shell_quote(method)
	if params then
		cmd = cmd .. " " .. shell_quote(json_encode(params))
	end

	local data = run(cmd)
	local parsed = json_decode(data)
	if parsed then
		sources["ubus:" .. object .. "." .. method] = true
	end

	return parsed
end

local function gather_dhcp_leases()
	local data = readfile("/tmp/dhcp.leases")
	if not data then
		return
	end

	sources["/tmp/dhcp.leases"] = true
	for line in data:gmatch("[^\r\n]+") do
		local expires, mac, ip, hostname, clientid = line:match("^(%S+)%s+(%S+)%s+(%S+)%s+(%S+)%s*(.*)$")
		if mac and ip then
			local dev = ensure_device(mac, ip, hostname)
			add_source(dev, "dhcp_leases")
			dev.dhcp_clientid = trim(clientid) or dev.dhcp_clientid
			dev.lease_expires = tonumber(expires) or dev.lease_expires
			add_fact(dev, "dhcp", string.format("lease ip=%s hostname=%s", ip, trim(hostname) or "unknown"))
		end
	end
end

local function gather_arp()
	local data = readfile("/proc/net/arp")
	if not data then
		return
	end

	sources["/proc/net/arp"] = true
	for line in data:gmatch("[^\r\n]+") do
		local ip, _, flags, mac, _, devname = line:match("^(%S+)%s+(%S+)%s+(%S+)%s+(%S+)%s+(%S+)%s+(%S+)")
		local norm = normalize_mac(mac)
		if norm and ip ~= "IP" then
			local dev = ensure_device(norm, ip)
			add_source(dev, "arp")
			dev.online = true
			add_interface(dev, devname)
			add_fact(dev, "arp", string.format("%s on %s flags=%s", ip, devname or "?", flags or "?"))
		end
	end
end

local function gather_ndp()
	local data = run("ip -6 neigh show")
	if data == "" then
		return
	end

	sources["ip -6 neigh"] = true
	for line in data:gmatch("[^\r\n]+") do
		local ip = trim(line:match("^(%S+)"))
		local devname = trim(line:match("%sdev%s+(%S+)"))
		local mac = normalize_mac(line:match("%slladdr%s+([%x:]+)"))
		local state = trim(line:match("%s([A-Z_]+)%s*$"))

		if ip and mac then
			local dev = ensure_device(mac, ip)
			add_source(dev, "ndp")
			dev.online = true
			add_interface(dev, devname)
			add_fact(dev, "ndp", string.format("%s on %s state=%s", ip, devname or "?", state or "?"))
		end
	end
end

local function gather_luci_host_hints()
	local hints = ubus_call("luci-rpc", "getHostHints")
	if type(hints) ~= "table" then
		return
	end

	for mac, hint in pairs(hints) do
		local norm = normalize_mac(mac)
		if norm and type(hint) == "table" then
			local dev = ensure_device(norm, hint.ipv4 or hint.ipaddr, hint.name or hint.hostname)
			add_source(dev, "ubus_host_hints")
			add_fact(dev, "ubus", "luci-rpc host hint")

			add_hostname(dev, hint.name or hint.hostname)
			add_ip(dev, hint.ipv4 or hint.ipaddr)

			if type(hint.ipaddrs) == "table" then
				for _, ip in ipairs(hint.ipaddrs) do
					add_ip(dev, ip)
				end
			end

			if type(hint.ip6addrs) == "table" then
				for _, ip in ipairs(hint.ip6addrs) do
					add_ip(dev, ip)
				end
			end
		end
	end
end

local function gather_ubus_dhcp_leases()
	local function visit(node, source)
		if type(node) ~= "table" then
			return
		end

		local mac = node.mac or node.macaddr or node["mac-address"] or node.duid
		local ip = node.ip or node.ipaddr or node.address or node["ip-address"] or node["ipv4-address"] or node["ipv6-address"]
		local hostname = node.hostname or node.name

		if normalize_mac(mac) or trim(ip) or trim(hostname) then
			local dev = ensure_device(mac, ip, hostname)
			add_source(dev, source)
			dev.online = true
			dev.dhcp_clientid = trim(node.clientid or node.client_id or node.client) or dev.dhcp_clientid
			add_fact(dev, "ubus", source)
		end

		for _, value in pairs(node) do
			if type(value) == "table" then
				visit(value, source)
			end
		end
	end

	local ipv4 = ubus_call("dhcp", "ipv4leases")
	if ipv4 then
		visit(ipv4, "ubus_dhcp_ipv4")
	end

	local ipv6 = ubus_call("dhcp", "ipv6leases")
	if ipv6 then
		visit(ipv6, "ubus_dhcp_ipv6")
	end
end

local function gather_hostapd_clients()
	local list = run("ubus -S list")
	if list == "" then
		return
	end

	for object in list:gmatch("[^\r\n]+") do
		if object:match("^hostapd%.") then
			local result = ubus_call(object, "get_clients")
			local clients = type(result) == "table" and (result.clients or result) or nil
			if type(clients) == "table" then
				for mac, info in pairs(clients) do
					local norm = normalize_mac(mac)
					if norm then
						local dev = ensure_device(norm)
						add_source(dev, "ubus_hostapd")
						dev.online = true
						add_interface(dev, object:gsub("^hostapd%.", ""))

						if type(info) == "table" then
							local signal = info.signal or info.signal_avg
							add_fact(dev, "ubus", string.format("%s client signal=%s", object, signal or "?"))
						else
							add_fact(dev, "ubus", object .. " client")
						end
					end
				end
			end
		end
	end
end

local function gather_network_status()
	local dump = ubus_call("network.interface", "dump")
	local interfaces = type(dump) == "table" and dump.interface or nil
	if type(interfaces) ~= "table" then
		return
	end

	for _, iface in ipairs(interfaces) do
		if type(iface) == "table" then
			network_interfaces[#network_interfaces + 1] = {
				interface = iface.interface,
				device = iface.device,
				l3_device = iface.l3_device,
				proto = iface.proto,
				up = iface.up and true or false
			}
		end
	end
end

local function clean_vendor(value)
	value = trim(value)
	if not value then
		return nil
	end

	value = value:gsub("[%c]", " ")
	value = trim(value)

	if not value or #value > 160 or value:find("<", 1, true) then
		return nil
	end

	return value
end

local function load_online_vendor_cache()
	online_vendor_cache_path = uci_get("deviceid.settings.online_vendor_cache", "/etc/deviceid/vendor-cache.json")
	online_vendor_stats.cache_file = online_vendor_cache_path

	local parsed = json_decode(readfile(online_vendor_cache_path))
	if type(parsed) ~= "table" then
		return
	end

	local entries = parsed.vendors or parsed
	if type(entries) == "table" then
		online_vendor_cache = entries
		sources["online_vendor_cache"] = true
	end
end

local function cache_entry_vendor(entry, ttl_days, negative_ttl_days)
	local vendor = nil
	local updated_at = nil

	if type(entry) == "table" then
		vendor = clean_vendor(entry.vendor or entry.name)
		updated_at = tonumber(entry.updated_at or entry.ts)
		if not vendor and trim(entry.status) then
			if not updated_at or negative_ttl_days <= 0 or os.time() - updated_at <= negative_ttl_days * 86400 then
				return nil, true
			end
		end
	elseif type(entry) == "string" then
		vendor = clean_vendor(entry)
	end

	if not vendor then
		return nil, false
	end

	if ttl_days and ttl_days > 0 and updated_at and os.time() - updated_at > ttl_days * 86400 then
		return nil, false
	end

	return vendor, true
end

local function cached_vendor(mac, ttl_days, negative_ttl_days)
	local key = normalize_mac_key(mac)
	if not key then
		return nil, false
	end

	return cache_entry_vendor(online_vendor_cache[key], ttl_days, negative_ttl_days)
end

local function store_cached_vendor(mac, vendor)
	local key = normalize_mac_key(mac)
	vendor = clean_vendor(vendor)
	if not key or not vendor then
		return
	end

	online_vendor_cache[key] = {
		vendor = vendor,
		updated_at = os.time(),
		source = "macvendors"
	}
	online_vendor_cache_dirty = true
end

local function store_negative_vendor_cache(mac, status)
	local key = normalize_mac_key(mac)
	if not key then
		return
	end

	online_vendor_cache[key] = {
		status = status or "not_found",
		updated_at = os.time(),
		source = "macvendors"
	}
	online_vendor_cache_dirty = true
end

local function fetch_url(url, timeout)
	local quoted_url = shell_quote(url)
	local timeout_arg = tostring(tonumber(timeout) or 4)

	if trim(run("command -v uclient-fetch")) then
		return clean_vendor(run("uclient-fetch -q -O - -T " .. timeout_arg .. " " .. quoted_url))
	end

	if trim(run("command -v wget")) then
		return clean_vendor(run("wget -qO- -T " .. timeout_arg .. " " .. quoted_url))
	end

	return nil
end

local function query_online_vendor(mac)
	local base = uci_get("deviceid.settings.online_vendor_api", "https://api.macvendors.com/")
	if not base:match("/$") then
		base = base .. "/"
	end

	local path_mac = (normalize_mac(mac) or mac):gsub(":", "-")
	return fetch_url(base .. path_mac, 2)
end

local function save_online_vendor_cache()
	if not online_vendor_cache_dirty or not online_vendor_cache_path then
		return
	end

	local dir = online_vendor_cache_path:match("^(.*)/[^/]+$")
	if dir then
		run("mkdir -p " .. shell_quote(dir))
	end

	local tmp = online_vendor_cache_path .. ".tmp"
	local fp = io.open(tmp, "w")
	if not fp then
		online_vendor_stats.errors = online_vendor_stats.errors + 1
		return
	end

	fp:write(json_encode({
		updated_at = os.time(),
		vendors = online_vendor_cache
	}))
	fp:write("\n")
	fp:close()

	if os.rename(tmp, online_vendor_cache_path) then
		sources["online_vendor_cache"] = true
	else
		online_vendor_stats.errors = online_vendor_stats.errors + 1
	end
end

local function apply_online_vendor_lookup(requested, request_limit)
	if not enabled("deviceid.settings.enable_online_vendor_lookup", "1") then
		online_vendor_stats.reason = "disabled_by_config"
		return
	end

	online_vendor_stats.enabled = true
	load_online_vendor_cache()

	local ttl_days = tonumber(uci_get("deviceid.settings.online_vendor_ttl_days", "90")) or 90
	local negative_ttl_days = tonumber(uci_get("deviceid.settings.online_vendor_negative_ttl_days", "7")) or 7
	local max_requests = tonumber(uci_get("deviceid.settings.online_vendor_max_requests", "5")) or 5
	request_limit = tonumber(request_limit)
	if request_limit and request_limit >= 0 then
		max_requests = request_limit
	end
	if max_requests < 0 then
		max_requests = 0
	end

	for _, dev in ipairs(devices) do
		if not dev.vendor and dev.mac then
			if not is_universal_unicast(dev.mac) then
				online_vendor_stats.skipped = online_vendor_stats.skipped + 1
				add_fact(dev, "online_vendor", "跳过本地管理/随机 MAC，OUI 厂商判断不可靠")
			else
				local vendor, cache_checked = cached_vendor(dev.mac, ttl_days, negative_ttl_days)
				if vendor then
					dev.vendor = vendor
					online_vendor_stats.cache_hits = online_vendor_stats.cache_hits + 1
					online_vendor_stats.checked = online_vendor_stats.checked + 1
					add_fact(dev, "online_vendor_cache", vendor)
				elseif cache_checked then
					online_vendor_stats.checked = online_vendor_stats.checked + 1
					add_fact(dev, "online_vendor_cache", "近期已在线查询但未返回厂商")
				elseif not requested then
					online_vendor_stats.reason = "cache_only"
					online_vendor_stats.remaining = online_vendor_stats.remaining + 1
				elseif online_vendor_stats.attempted < max_requests then
					if online_vendor_stats.attempted > 0 then
						run("sleep 1")
					end

					online_vendor_stats.attempted = online_vendor_stats.attempted + 1
					vendor = query_online_vendor(dev.mac)
					if vendor then
						dev.vendor = vendor
						store_cached_vendor(dev.mac, vendor)
						sources["macvendors.com"] = true
						online_vendor_stats.found = online_vendor_stats.found + 1
						online_vendor_stats.checked = online_vendor_stats.checked + 1
						add_fact(dev, "macvendors.com", vendor)
					else
						store_negative_vendor_cache(dev.mac, "not_found")
						online_vendor_stats.errors = online_vendor_stats.errors + 1
						online_vendor_stats.checked = online_vendor_stats.checked + 1
						add_fact(dev, "macvendors.com", "未查询到厂商或在线请求失败")
					end
				else
					online_vendor_stats.skipped = online_vendor_stats.skipped + 1
					online_vendor_stats.remaining = online_vendor_stats.remaining + 1
					add_fact(dev, "online_vendor", "已达到本次扫描在线查询上限")
				end
			end
		end
	end

	if requested then
		online_vendor_stats.reason = online_vendor_stats.remaining > 0 and "partial" or "complete"
	elseif not online_vendor_stats.reason then
		online_vendor_stats.reason = "cache_only"
	end

	save_online_vendor_cache()
end

local function find_device_for_service(record)
	if not record then
		return nil
	end

	if record.mac and by_mac[normalize_mac(record.mac)] then
		return by_mac[normalize_mac(record.mac)]
	end

	local candidates = {}
	local function add_candidate(value)
		value = trim(value)
		if value then
			candidates[#candidates + 1] = value
		end
	end

	add_candidate(record.ip)
	add_candidate(record.address)
	add_candidate(record.ipv4)
	add_candidate(record.ipv6)
	add_candidate(record.hostname)
	add_candidate(record.host)
	add_candidate(record.name)

	if type(record.addresses) == "table" then
		for _, value in ipairs(record.addresses) do
			add_candidate(value)
		end
	end

	for _, value in ipairs(candidates) do
		if by_ip[value] then
			return by_ip[value]
		end

		local lower = value:lower():gsub("%.local%.?$", "")
		if by_hostname[lower] then
			return by_hostname[lower]
		end
	end

	return nil
end

local function gather_umdns()
	if not enabled("deviceid.settings.enable_mdns", "1") then
		return
	end

	local data = ubus_call("umdns", "browse", { timeout = 200 })
	if type(data) ~= "table" then
		return
	end

	local function visit(node, path)
		if type(node) ~= "table" then
			return
		end

		local service = nil
		for i = #path, 1, -1 do
			local value = tostring(path[i])
			if value:match("^_") or value:find("upnp", 1, true) then
				service = value
				break
			end
		end

		local dev = find_device_for_service(node)
		if dev and service then
			add_source(dev, "mdns")
			add_service(dev, service, node.host or node.hostname or node.name)

			if type(node.txt) == "table" then
				for _, txt in ipairs(node.txt) do
					add_service(dev, tostring(txt), service)
				end
			end
		end

		for key, value in pairs(node) do
			if type(value) == "table" then
				path[#path + 1] = key
				visit(value, path)
				path[#path] = nil
			end
		end
	end

	visit(data, {})
end

local function gather_service_hints()
	if not enabled("deviceid.settings.enable_service_hints", "1") then
		return
	end

	local paths = {
		"/tmp/deviceid/services.json",
		"/etc/deviceid/services.json"
	}

	for _, path in ipairs(paths) do
		local parsed = json_decode(readfile(path))
		local list = parsed and (parsed.devices or parsed.hosts or parsed)
		if type(list) == "table" then
			sources[path] = true
			for _, record in ipairs(list) do
				if type(record) == "table" then
					local dev = ensure_device(record.mac, record.ip or record.ipv4 or record.ipv6, record.hostname or record.host or record.name)
					add_source(dev, "service_hints")
					add_fact(dev, "service_hint", path)

					if trim(record.vendor or record.manufacturer) then
						dev.vendor = trim(record.vendor or record.manufacturer)
					end

					if trim(record.model) then
						add_service(dev, record.model, "model")
					end

					if type(record.services) == "table" then
						for _, service in ipairs(record.services) do
							add_service(dev, service, path)
						end
					elseif trim(record.service) then
						add_service(dev, record.service, path)
					end
				end
			end
		end
	end
end

local function self_macs()
	local macs = {}
	local p = io.popen("ls /sys/class/net 2>/dev/null")
	if not p then return macs end
	for line in p:lines() do
		local fh = io.open("/sys/class/net/" .. line .. "/address")
		if fh then
			local mac = normalize_mac(fh:read("*l"))
			fh:close()
			if mac then macs[mac] = true end
		end
	end
	p:close()
	return macs
end

local function gather_all()
	gather_dhcp_leases()
	gather_arp()
	gather_ndp()
	gather_luci_host_hints()
	gather_ubus_dhcp_leases()
	gather_hostapd_clients()
	gather_network_status()
	gather_umdns()
	gather_service_hints()
end

local function mark_blocked_devices(blocked_map)
	for _, dev in ipairs(devices) do
		local mac = normalize_mac(dev.mac)
		dev.blocked = mac ~= nil and blocked_map[mac] ~= nil
		if dev.blocked then
			add_source(dev, "access_control")
			add_fact(dev, "access_control", "已配置为断网")
		end
	end
end

local function flush_conntrack(ip)
	local conntrack = command_path("conntrack", "/usr/sbin/conntrack")

	run(conntrack .. " -D -s " .. shell_quote(ip))
	run(conntrack .. " -D -d " .. shell_quote(ip))
end

local function reset_access_table(nft)
	run(nft .. " delete table inet deviceid")
	run(nft .. " add table inet deviceid")
	run(nft .. " add chain inet deviceid prerouting " .. shell_quote("{ type filter hook prerouting priority raw; policy accept; }"))
	run(nft .. " add chain inet deviceid forward " .. shell_quote("{ type filter hook forward priority filter; policy accept; }"))
end

local function clear_block_rules()
	local nft = command_path("nft", "/usr/sbin/nft")
	run(nft .. " delete table inet deviceid")
	return {
		ok = true,
		rules = 0,
		blocked_devices = 0
	}
end

local function apply_block_rules()
	local nft = command_path("nft", "/usr/sbin/nft")
	local blocked_map, blocked_list = load_blocked_map()
	local applied = {}
	local rules = 0

	if #blocked_list == 0 then
		return clear_block_rules()
	end

	if #devices == 0 then
		gather_all()
	end

	reset_access_table(nft)

	for _, dev in ipairs(devices) do
		local mac = normalize_mac(dev.mac)
		if mac and blocked_map[mac] then
			local entry = {
				mac = mac,
				hostname = dev.hostnames[1],
				ipv4 = {},
				ipv6 = {}
			}

			for _, ip in ipairs(dev.ipv4) do
				entry.ipv4[#entry.ipv4 + 1] = ip
				run(nft .. " add rule inet deviceid prerouting ip saddr " .. shell_quote(ip) .. " counter drop")
				run(nft .. " add rule inet deviceid forward ip saddr " .. shell_quote(ip) .. " counter drop")
				run(nft .. " add rule inet deviceid forward ip daddr " .. shell_quote(ip) .. " counter drop")
				flush_conntrack(ip)
				rules = rules + 3
			end

			for _, ip in ipairs(dev.ipv6) do
				if not ip:lower():match("^fe80:") then
					entry.ipv6[#entry.ipv6 + 1] = ip
					run(nft .. " add rule inet deviceid prerouting ip6 saddr " .. shell_quote(ip) .. " counter drop")
					run(nft .. " add rule inet deviceid forward ip6 saddr " .. shell_quote(ip) .. " counter drop")
					run(nft .. " add rule inet deviceid forward ip6 daddr " .. shell_quote(ip) .. " counter drop")
					flush_conntrack(ip)
					rules = rules + 3
				end
			end

			applied[#applied + 1] = entry
		end
	end

	return {
		ok = true,
		rules = rules,
		blocked_devices = #blocked_list,
		applied_devices = applied
	}
end

local function set_device_blocked(mac, blocked, name)
	local section

	mac = normalize_mac(mac)
	if not mac then
		return {
			ok = false,
			error = "invalid_mac"
		}
	end

	section = find_block_section(mac)
	if not section then
		section = trim(run("uci add deviceid block"))
	end

	section = safe_uci_section(section)
	if not section then
		return {
			ok = false,
			error = "uci_section_failed"
		}
	end

	uci_set_option(section, "mac", mac)
	uci_set_option(section, "enabled", blocked and "1" or "0")

	if trim(name) then
		uci_set_option(section, "name", trim(name))
	end

	os.execute("uci -q commit deviceid")

	local applied = apply_block_rules()
	applied.ok = applied.ok ~= false
	applied.mac = mac
	applied.blocked = blocked and true or false
	return applied
end

local function load_oui_map()
	local paths = {
		"/usr/share/deviceid/oui.json",
		uci_get("deviceid.settings.custom_oui", "/etc/deviceid/oui.json")
	}
	local map = {}

	for _, path in ipairs(paths) do
		if path and file_exists(path) then
			local parsed = json_decode(readfile(path))
			local entries = parsed and (parsed.ouis or parsed)
			if type(entries) == "table" then
				loaded_oui_files[#loaded_oui_files + 1] = path
				for key, value in pairs(entries) do
					local oui = normalize_oui(key)
					if oui then
						map[oui] = value
					end
				end
			end
		end
	end

	return map
end

local function apply_oui(map)
	for _, dev in ipairs(devices) do
		local oui = normalize_oui(dev.mac)
		local entry = oui and map[oui]
		if entry then
			if type(entry) == "table" then
				dev.vendor = trim(entry.vendor or entry.name or entry.manufacturer) or dev.vendor
				if type(entry.hints) == "table" then
					for _, hint in ipairs(entry.hints) do
						add_service(dev, hint, "oui_hint")
					end
				end
			else
				dev.vendor = trim(entry) or dev.vendor
			end

			if dev.vendor then
				add_fact(dev, "oui", string.format("%s => %s", oui, dev.vendor))
			end
		end
	end
end

local function load_rules()
	local paths = {
		"/usr/share/deviceid/rules.json",
		uci_get("deviceid.settings.custom_rules", "/etc/deviceid/rules.json")
	}
	local rules = {}

	for _, path in ipairs(paths) do
		if path and file_exists(path) then
			local parsed = json_decode(readfile(path))
			local list = parsed and (parsed.rules or parsed)
			if type(list) == "table" then
				loaded_rule_files[#loaded_rule_files + 1] = path
				for _, rule in ipairs(list) do
					if type(rule) == "table" and type(rule.match) == "table" then
						rule._source_file = path
						rules[#rules + 1] = rule
					end
				end
			end
		end
	end

	return rules
end

local function list_values(dev, field)
	if field == "hostname" or field == "hostnames" then
		return dev.hostnames
	elseif field == "service" or field == "services" then
		local values = {}
		for _, item in ipairs(dev.services) do
			values[#values + 1] = item
		end
		for _, item in ipairs(dev.service_details) do
			values[#values + 1] = item
		end
		return values
	elseif field == "vendor" or field == "manufacturer" then
		return { dev.vendor or "" }
	elseif field == "mac" or field == "mac_prefix" then
		return { dev.mac or "" }
	elseif field == "ip" or field == "address" then
		local values = {}
		for _, ip in ipairs(dev.ipv4) do
			values[#values + 1] = ip
		end
		for _, ip in ipairs(dev.ipv6) do
			values[#values + 1] = ip
		end
		return values
	elseif field == "dhcp_clientid" or field == "clientid" then
		return { dev.dhcp_clientid or "" }
	elseif field == "source" or field == "sources" then
		local values = {}
		for source in pairs(dev.sources) do
			values[#values + 1] = source
		end
		return values
	end

	return { "" }
end

local function pattern_list(value)
	if type(value) == "table" then
		return value
	elseif value ~= nil then
		return { value }
	end
	return {}
end

local function matches_field(dev, field, patterns)
	local values = list_values(dev, field)

	for _, raw_pattern in ipairs(pattern_list(patterns)) do
		local pattern = trim(raw_pattern)
		if pattern then
			for _, raw_value in ipairs(values) do
				local value = trim(raw_value)
				if value then
					if field == "mac_prefix" then
						local lhs = value:upper():gsub("[^0-9A-F]", "")
						local rhs = pattern:upper():gsub("[^0-9A-F]", "")
						if rhs ~= "" and lhs:sub(1, #rhs) == rhs then
							return { field = field, value = value, pattern = pattern }
						end
					elseif value:lower():find(pattern:lower(), 1, true) then
						return { field = field, value = value, pattern = pattern }
					end
				end
			end
		end
	end

	return nil
end

local function match_rule(dev, rule)
	local matches = {}

	for field, patterns in pairs(rule.match or {}) do
		local matched = matches_field(dev, field, patterns)
		if not matched then
			return nil
		end
		matches[#matches + 1] = matched
	end

	return matches
end

local function add_candidate(candidates, rule, matches)
	local label = trim(rule.label) or trim(rule.name) or trim(rule.type) or "未知设备"
	local dtype = trim(rule.type) or "unknown"
	local score = tonumber(rule.score or rule.confidence) or 50
	local key = dtype .. "\n" .. label

	if not candidates[key] then
		candidates[key] = {
			type = dtype,
			label = label,
			score = 0,
			evidence = {}
		}
	end

	local candidate = candidates[key]
	candidate.score = math.min(99, candidate.score + score)

	local detail = trim(rule.evidence) or trim(rule.description) or trim(rule.id) or "rule matched"
	local pieces = {}
	for _, match in ipairs(matches or {}) do
		pieces[#pieces + 1] = string.format("%s=%s", match.field, match.value)
	end

	if #pieces > 0 then
		detail = detail .. " (" .. table.concat(pieces, ", ") .. ")"
	end

	candidate.evidence[#candidate.evidence + 1] = {
		source = "rule:" .. (trim(rule.id) or label),
		score = score,
		detail = detail
	}
end

local function score_device(dev, rules)
	local candidates = {}

	for _, rule in ipairs(rules) do
		local matches = match_rule(dev, rule)
		if matches then
			add_candidate(candidates, rule, matches)
		end
	end

	local best = nil
	for _, candidate in pairs(candidates) do
		if not best or candidate.score > best.score then
			best = candidate
		end
	end

	if not best then
		local label = dev.vendor and ("疑似 " .. dev.vendor .. " 设备") or "未知设备"
		best = {
			type = "unknown",
			label = label,
			score = dev.vendor and 24 or 10,
			evidence = {}
		}

		if dev.vendor then
			best.evidence[#best.evidence + 1] = {
				source = "oui",
				score = 24,
				detail = "只有厂商信息，无法进一步判断类型"
			}
		end
	end

	local fact_bonus = 0
	if dev.vendor then
		fact_bonus = fact_bonus + 3
	end
	if #dev.hostnames > 0 then
		fact_bonus = fact_bonus + 3
	end
	if #dev.services > 0 then
		fact_bonus = fact_bonus + 4
	end
	if dev.sources.arp or dev.sources.ndp or dev.sources.ubus_hostapd then
		fact_bonus = fact_bonus + 2
	end

	dev.type = best.type
	dev.label = best.label
	dev.confidence = math.min(99, best.score + fact_bonus)
	dev.evidence = best.evidence
end

local function sorted_keys(map)
	local list = {}
	for key in pairs(map) do
		list[#list + 1] = key
	end
	table.sort(list)
	return list
end

local function flatten_device(dev)
	table.sort(dev.ipv4)
	table.sort(dev.ipv6)
	table.sort(dev.hostnames)
	table.sort(dev.interfaces)
	table.sort(dev.services)
	table.sort(dev.service_details)

	return {
		mac = dev.mac,
		ipv4 = dev.ipv4,
		ipv6 = dev.ipv6,
		hostname = dev.hostnames[1],
		hostnames = dev.hostnames,
		vendor = dev.vendor,
		interfaces = dev.interfaces,
		services = dev.services,
		service_details = dev.service_details,
		sources = sorted_keys(dev.sources),
		online = dev.online,
		blocked = dev.blocked,
		lease_expires = dev.lease_expires,
		dhcp_clientid = dev.dhcp_clientid,
		type = dev.type,
		label = dev.label,
		confidence = dev.confidence,
		evidence = dev.evidence,
		facts = dev.facts
	}
end

local function sort_devices(a, b)
	local ah = (a.hostnames[1] or a.ipv4[1] or a.ipv6[1] or a.mac or ""):lower()
	local bh = (b.hostnames[1] or b.ipv4[1] or b.ipv6[1] or b.mac or ""):lower()
	return ah < bh
end

local function main()
	local action = arg and arg[1] or "scan"
	local request = json_decode(io.read("*a") or "") or {}

	if action == "set_blocked" then
		print(json_encode(set_device_blocked(request.mac, value_enabled(request.blocked, false), request.name or request.hostname)))
		return
	elseif action == "apply_blocks" then
		print(json_encode(apply_block_rules()))
		return
	elseif action == "clear_blocks" then
		print(json_encode(clear_block_rules()))
		return
	end

	gather_all()

	apply_oui(load_oui_map())
	apply_online_vendor_lookup(request.online == true or request.online == "1" or request.online == 1, request.limit)
	local blocked_map, blocked_list = load_blocked_map()
	local access_control = {
		ok = true,
		blocked_devices = #blocked_list,
		applied_on_scan = false
	}
	mark_blocked_devices(blocked_map)
	if #blocked_list > 0 then
		access_control = apply_block_rules()
		access_control.applied_on_scan = true
	end
	local rules = load_rules()

	table.sort(devices, sort_devices)
	local self = self_macs()
	local output_devices = {}
	for _, dev in ipairs(devices) do
		local dmac = normalize_mac(dev.mac)
		if self[dmac] then
			goto continue
		end

		local has_real_ip = false
		for _, ip in ipairs(dev.ipv4) do
			if ip and ip ~= "0.0.0.0" then has_real_ip = true break end
		end
		if not has_real_ip then
			for _, ip in ipairs(dev.ipv6) do
				if ip and ip ~= "::1" and not ip:lower():match("^fe80::1$") then has_real_ip = true break end
			end
		end
		if not has_real_ip then
			goto continue
		end

		if not dev.online and not dev.blocked then
			goto continue
		end

		score_device(dev, rules)
		output_devices[#output_devices + 1] = flatten_device(dev)
		::continue::
	end

	print(json_encode({
		version = VERSION,
		generated_at = os.time(),
		device_count = #output_devices,
		sources = sorted_keys(sources),
		rule_files = loaded_rule_files,
		oui_files = loaded_oui_files,
		online_vendor_lookup = online_vendor_stats,
		access_control = access_control,
		network_interfaces = network_interfaces,
		devices = output_devices
	}))
end

main()
