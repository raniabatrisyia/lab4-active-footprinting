# Lab 4: Active Footprinting

**Name:** RANIA BATRISYIA BINTI ABDUL RAHIM
**ID:** 52215125343
**Class:** [write your class here]
**Testing date:** 18 November 2026
**Submission date:** 20 November 2026

## 1. Introduction

This lab is about active footprinting. In the passive lab I only looked at public information, but here I send traffic straight to a target and study how it replies. I picked two intentionally vulnerable training applications, DVWA and OWASP Juice Shop, and ran them myself in Docker so I know I am allowed to test them.

I kept everything to scanning and fingerprinting. I did not log in, exploit anything, brute-force anything or try to break the services.

## 2. Target Setup (Victims)

Both targets run as Docker containers on the same Kali Linux virtual machine. I installed Docker with `sudo apt install -y docker.io` (Figure 1), then started DVWA from the image `vulnerables/web-dvwa` on port 80 (Figure 2) and Juice Shop from `bkimminich/juice-shop` on port 3000 (Figure 3). `docker ps` shows that both containers were up and running (Figure 4).

![Figure 1: Docker installation on Kali](images/01_docker_install.png)
*Figure 1: Docker installation on Kali*

![Figure 2: DVWA container started on port 80](images/02_dvwa_run.png)
*Figure 2: DVWA container started on port 80*

![Figure 3: Juice Shop container started on port 3000](images/03_juice_run.png)
*Figure 3: Juice Shop container started on port 3000*

![Figure 4: Running containers shown by docker ps](images/04_docker_ps.png)
*Figure 4: Running containers shown by docker ps*

To be sure which IP belongs to which container, I used `docker inspect`. It shows that /dvwa has the IP 172.17.0.2 and /juice has the IP 172.17.0.3 (Figure 5). Both sit on the default Docker bridge network, 172.17.0.0/16 (docker0). These are training applications and not real systems, and I only tested containers that I own.

![Figure 5: Container names mapped to their IP addresses](images/05_docker_inspect.png)
*Figure 5: Container names mapped to their IP addresses*

## 3. Own Host (Attacker)

The attacker is a Kali Linux virtual machine with the hostname `kali` and kernel 7.1.5-kali-amd64. Its eth0 interface has the IP 10.0.2.4/24 and the default gateway is 10.0.2.1, which fits VirtualBox NAT. The docker0 interface has the IP 172.17.0.1/16 and works as the gateway for the network where the two containers run (Figure 6). The tools I used were Nmap 7.99, curl and WhatWeb. The attacker and the targets are on the same machine.

![Figure 6: Attacker host information](images/06_attacker_info.png)
*Figure 6: Attacker host information (hostname, kernel, IP addresses, routes and Nmap version)*

## 4. Findings, Evidence and Analysis

### 4.1 Host discovery

I ran `nmap -sn 172.17.0.0/24` at 08:34 on 18 November 2026 (Kali clock, UTC-5). It found 3 hosts up out of 256 addresses in 3.06 seconds: 172.17.0.1 (the docker0 interface of my own machine), 172.17.0.2 and 172.17.0.3 (Figure 7, highlighted in red). The MAC vendor is shown as "Unknown", which is normal for virtual Docker interfaces.

Host discovery only lists hosts that answer the probes. A host that blocks them would not appear, so this result could miss hosts (a false negative).

![Figure 7: Host discovery](images/07_host_discovery.png)
*Figure 7: Host discovery on 172.17.0.0/24, with the two target hosts highlighted*

### 4.2 Open ports and services

The service scan (`nmap -sV`) found only port 80/tcp open on 172.17.0.2, running Apache httpd 2.4.25 (Debian). On 172.17.0.3 only port 3000/tcp was open (Figure 8). Nmap labelled port 3000 as `ppp?`. That is only the default name Nmap gives that port number, and the question mark means it could not confirm the service. The response Nmap captured is a normal HTTP page with the title "OWASP Juice Shop", so it is a web application.

![Figure 8: Service detection](images/08_nmap_sV.png)
*Figure 8: Service detection with nmap -sV*

The `-sV -sC` scan on ports 80 and 3000 gave the same picture. Port 3000 was closed on 172.17.0.2 and port 80 was closed on 172.17.0.3, so each container only exposes its own application port (Figures 9 and 10).

![Figure 9: nmap -sV -sC part 1](images/09_nmap_sC_part1.png)
*Figure 9: nmap -sV -sC on ports 80 and 3000 (part 1)*

![Figure 10: nmap -sV -sC part 2](images/10_nmap_sC_part2.png)
*Figure 10: nmap -sV -sC on ports 80 and 3000 (part 2)*

I also did a full TCP port scan (`nmap -p- --open`). It confirmed that nothing else is open: 65534 ports were closed on each host (Figure 11). The ports were reported as "closed (reset)" and not "filtered", which suggests nothing is dropping traffic between my machine and the containers.

![Figure 11: Full TCP port scan](images/11_nmap_full_ports.png)
*Figure 11: Full TCP port scan of both targets*

### 4.3 Web fingerprinting

For the web side I used `curl -I` for the headers (Figure 12), WhatWeb (Figure 13), the Nmap scripts `http-methods`, `http-headers` and `http-title` (Figure 14), and I also asked for the `robots.txt` file of each target (Figure 15). DVWA gives away its web server and version, while Juice Shop does not send a Server or X-Powered-By header, so it shows less about its technology. Neither response included a Content-Security-Policy or Strict-Transport-Security header.

![Figure 12: HTTP headers](images/12_curl_headers.png)
*Figure 12: HTTP response headers of DVWA and Juice Shop (curl -I)*

![Figure 13: WhatWeb](images/13_whatweb.png)
*Figure 13: WhatWeb results for both targets*

![Figure 14: HTTP methods](images/14_http_methods.png)
*Figure 14: HTTP methods, headers and title from Nmap scripts*

![Figure 15: robots.txt](images/15_robots_txt.png)
*Figure 15: robots.txt of DVWA and Juice Shop*

### 4.4 DVWA (172.17.0.2, port 80)

DVWA answered with `302 Found` and redirected to `login.php` (Figure 12). The Server header shows `Apache/2.4.25 (Debian)`. WhatWeb picked up PHP and a password field (Figure 13), and the page title is "Login :: Damn Vulnerable Web Application (DVWA) v1.10 *Development*" (Figures 14 and 16). The site sets two cookies, `PHPSESSID` and `security=low`, and Nmap reports that the HttpOnly flag is not set on PHPSESSID (Figure 9). The allowed methods are GET, HEAD, POST and OPTIONS, with no PUT, DELETE or TRACE (Figure 14). The robots.txt file says `Disallow: /` (Figure 15).

![Figure 16: DVWA in browser](images/16_dvwa_browser.png)
*Figure 16: DVWA login page opened in the browser*

### 4.5 Juice Shop (172.17.0.3, port 3000)

Juice Shop answered `200 OK` with these headers: `Access-Control-Allow-Origin: *`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: SAMEORIGIN`, `Feature-Policy: payment 'self'` and a custom `X-Recruiting: /#/jobs` header (Figure 12). WhatWeb found HTML5 and a JavaScript module script, and the title is "OWASP Juice Shop" (Figures 13 and 17).

The Nmap `http-methods` script returned nothing for this port, because Nmap did not treat the service as HTTP (Figure 14). To fill that gap I sent one manual request with `curl -i -X OPTIONS` on 19 November 2026 at 07:01 GMT, which was a different session from the Nmap scans. It returned `204 No Content` with `Access-Control-Allow-Methods: GET,HEAD,PUT,PATCH,POST,DELETE` (Figure 18). That header only describes what the server advertises for cross-origin requests. It does not prove that every method is accepted or can be abused. The CORS value of * means any website can read the responses. The robots.txt file says `Disallow: /ftp` (Figure 15). I noted this path but did not open it.

![Figure 17: Juice Shop in browser](images/17_juice_browser.png)
*Figure 17: Juice Shop homepage opened in the browser*

![Figure 18: OPTIONS request](images/18_juice_options.png)
*Figure 18: OPTIONS request sent to Juice Shop*

### 4.6 No transport encryption

Both applications use plain HTTP on ports 80 and 3000. The browser marks both pages as "Not Secure" (Figures 16 and 17) and the full port scan shows port 443 is not open (Figure 11). Anything sent to these services, such as a password or a session cookie, would travel unencrypted.

### 4.7 Summary of findings

| Finding | Evidence | Time | What it means | Confidence |
|---|---|---|---|---|
| 3 hosts up on 172.17.0.0/24 | nmap -sn (Fig. 7) | 18 Nov, 08:34 | Targets are 172.17.0.2 and 172.17.0.3 | High |
| .2 is DVWA, .3 is Juice Shop | docker inspect (Fig. 5) | 19 Nov, 07:01 GMT | Confirms which container has which IP | High |
| Apache 2.4.25 on port 80 | nmap -sV, curl -I (Fig. 8, 12) | 18 Nov, 08:37 to 08:42 | Version as reported by the banner. Not checked for vulnerabilities | High for the banner |
| Port 3000 is labelled ppp? | nmap -sV, WhatWeb, browser (Fig. 8, 13, 17) | 18 Nov, 08:37 to 08:46 | It is a web app (Juice Shop). The Nmap label is only a guess | High |
| Only ports 80 and 3000 open | nmap -p- (Fig. 11) | 18 Nov, 08:42 | Small exposed surface (TCP only) | High |
| HttpOnly not set on PHPSESSID | nmap -sC (Fig. 9) | 18 Nov, 08:39 | Session cookie can be read by scripts in the browser | Medium to high |
| CORS allows *, methods include PUT and DELETE | curl -X OPTIONS (Fig. 18) | 19 Nov, 07:01 GMT | Advertised policy only, not proven to be accepted | Medium |
| No HTTPS | Port scan, browser (Fig. 11, 16, 17) | 18 Nov, 08:42 | Traffic is sent in plain text | High |

## 5. Interpretation

The version numbers and headers show what each service says about itself. They do not confirm that a vulnerability exists. Banners can be hidden or changed, and a missing header or cookie flag is a weak configuration, not proof that anything was exploited. A vulnerability should only be called confirmed after it has been properly checked in an authorized test. This report does not claim any confirmed vulnerability.

## 6. Limitations

- The Nmap scans are a snapshot from 18 November 2026, 08:34 to 08:46 (UTC-5). The docker inspect and OPTIONS checks were done later, on 19 November 2026 at 07:01 GMT.
- Only TCP ports were scanned. I did not test UDP.
- Nmap could not identify the Juice Shop service (ppp?) and its HTTP scripts gave no output, so the header and method details for it came from curl and WhatWeb.
- The attacker and the targets share one VM on a Docker bridge, so the results do not show how real network defences such as a firewall, WAF or IDS would behave.
- Version detection depends on banners and can be wrong.
- No login, exploitation, brute-force or destructive testing was done.

## 7. Recommendations

- Hide version details on the web server, for example with `ServerTokens Prod` and `ServerSignature Off` in Apache.
- Set the HttpOnly and Secure flags on session cookies.
- Add security headers such as Content-Security-Policy, X-Frame-Options and Strict-Transport-Security.
- Limit CORS to trusted origins instead of using `*`.
- Serve the applications over HTTPS.
- Turn off HTTP methods that are not needed.
- Publish container ports only where needed, for example `-p 127.0.0.1:80:80`, instead of on all interfaces.
- Keep the software patched.

## Evidence files

The raw Nmap output is in the [`evidence/`](evidence/) folder.
