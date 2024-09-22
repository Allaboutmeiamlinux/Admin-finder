import requests
import threading
from queue import Queue
import time
from colorama import Fore, Style, init
from tqdm import tqdm
import random
import argparse
import json

# Initialize colorama for colored terminal output
init(autoreset=True)

# User-Agent list to randomize headers
user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
    "Mozilla/5.0 (Windows NT 10.0; Linux x86_64; rv:80.0) Gecko/20100101 Firefox/80.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.1 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 13_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0 Safari/605.1.15"
]

# An even larger expanded default common directories list
default_common_directories = [
    "admin", "administrator", "login", "dashboard", "manage", "cpanel", "adminpanel",
    "backend", "server", "user", "auth", "controlpanel", "account", "config", "adminlogin",
    "adminarea", "staff", "secure", "panel", "moderator", "root", "system", "api", 
    "wp-admin", "wp-login", "cms", "shop", "store", "siteadmin", "webadmin", "console", 
    "member", "members", "portal", "login.php", "admin.php", "home", "manager", "secureadmin", 
    "webmaster", "secret", "private", "test", "staging", "development", "assets", "includes", 
    "webroot", "data", "backup", "rest", "json", "xml", "public", "admin-console", 
    "admin-console-login", "shell", "shell-access", "upload", "download", "uploads", 
    "downloads", "dev", "devadmin", "portaladmin", "beta", "logs", "status", "services", 
    "configurations", "environments", "private", "index", "web-config", "host", "monitor", 
    "debug", "control", "stat", "phpmyadmin", "database", "phpinfo", "report", "error", 
    "errors", "settings", "config.php", "maintenance", "debugging", "tools", "support", 
    "errors", "php-error", "migration", "admincp", "dba", "sysadmin", "security", "infra", 
    "cloud", "resource", "resources", "service", "sys", "phpadmin", "webconfig", "vps", "mod", 
    "moderation", "operator", "admin-user", "superadmin", "rootadmin", "admin_tools", 
    "admin_login", "webmaster-tools", "syslogin", "staffpanel", "edit", "signin", "superuser", 
    "edit", "dashboardadmin", "logon", "author", "admin_area", "configuration", "projectadmin", 
    "testsite", "project", "hosting", "testpanel", "backendadmin", "platform", "reports", 
    "crm", "app", "supervisor", "systemadmin", "admin_portal", "operations", "editor", 
    "backendpanel", "moduleadmin", "developer", "sysconfig", "errorpages", "controladmin", 
    "sysconfig", "office", "adminzone", "ops", "backoffice", "managementpanel", "serveradmin", 
    "userconfig", "filemanager", "supermod", "accounts", "databases", "dashboard", "setup",
    "siteconfig", "operationsadmin", "webdashboard", "managementadmin", "statuspanel", 
    "backupadmin", "rootpanel", "myadmin", "fileadmin", "webcontrol", "configbackup",
    "application", "business", "sysdev", "managerlogin", "servicelogin", "rootconfig",
    "sysconsole", "files", "backupmanager", "appadmin", "loginsystem", "internaladmin", 
    "rootmanager", "databaselogin", "adminhome", "remotelogin", "sysadminportal", 
    "modpanel", "restricted", "securepanel", "firewall", "netadmin", "itadmin", "syssettings",
    "admincenter", "supportadmin", "moderationpanel", "logaccess", "dblogin", "statistics",
    "remoteaccess", "securelogin", "securearea", "adminzone", "restrictedaccess", 
    "serverstatus", "uploadmanager", "uploader", "fileadmin", "backupfiles", "mailadmin",
    "emailadmin", "mailer", "maileradmin", "taskmanager", "jobsadmin", "recovery", "dnsadmin", 
    "intranet", "sysinfo", "webdata", "appmanager", "filesadmin", "admindashboard", 
    "systemlogs", "monitoring", "monitoradmin", "serverconfig", "projectmanagement", 
    "usermanagement", "siteadminpanel", "portalconfig", "debuglog", "environment", 
    "syslogs", "configsystem", "dbmanager", "backuprestore", "pluginadmin", "pluginconfig",
    "resourceadmin", "performance", "license", "lockdown", "firewallconfig", "banned", 
    "hostmanager", "ipconfig", "installer", "webinstaller", "admininterface", "userfiles", 
    "sysadminaccess", "rootlogin", "publicpanel", "metrics", "statusadmin", "devtools",
    "developmentpanel", "usermgmt", "domainadmin", "adminfiles", "testconfig", "rootaccess",
    "administrator-login", "auth-user", "supermoderator", "system-config", "admin-config", 
    "phpmyadminlogin", "control-panel", "super-admin", "site-admin", "admin-backend", 
    "admindashboard", "securitycenter", "sys-console", "wp-config", "myadminpanel", 
    "access-admin", "admin-portal", "app-dashboard", "data-manager", "file-backup", 
    "sysadmin-dashboard", "webmaster-admin", "hostadmin", "control-room", "server-console", 
    "file-storage", "plugin-manager", "sys-admin-tools", "secure-root", "restricted-access",
    "system-admin-portal", "debug-console", "admin-api", "app-config", "debug-logs", 
    "maintenance-admin", "server-logs", "server-control-panel", "performance-monitor", 
    "security-logs", "admin-control-room", "logs-admin", "server-operations", 
    "user-authentication", "error-handler", "config-editor", "user-access", 
    "access-logs", "site-maintenance", "backup-dashboard", "plugin-config", 
    "email-settings", "mail-server", "web-storage", "admin-support", "error-monitor", 
    "account-settings", "db-backup", "config-backup", "system-errors", "system-settings", 
    "plugin-backend", "firewall-logs", "network-admin", "system-logs", "user-monitoring", 
    "login-system", "account-management", "admin-reports", "phpmyadmin-access", "app-admin-panel", 
    "db-access", "user-management", "dev-portal", "root-management", "admin-root-access", 
    "system-monitoring", "secure-admin", "admin-lockdown", "phpinfo-access", "admin-editor", 
    "admin-manager", "superuser-dashboard", "adminconsole", "remote-admin", "sysadmin-console",
    "user-access-logs", "root-config", "debug-access", "php-login", "root-control", 
    "config-console", "server-settings", "admin-metrics", "access-manager", "config-control", 
    "file-control", "debug-manager", "error-config", "user-root", "admin-root", 
    "root-settings", "system-configurations", "admin-performance", "login-portal", 
    "user-debug", "admin-error", "user-console", "login-config", "error-logs", 
    "config-logs", "system-authentication", "root-backup", "security-access", "logs-root"
]



# An expanded list of common subdomains
common_subdomains = [
    "admin", "cpanel", "webmail", "mail", "server", "dashboard", "portal", "ftp", "test", 
    "dev", "beta", "api", "blog", "shop", "store", "support", "docs", "status", "staging", 
    "beta", "secure", "www", "old", "m", "mail2", "webdisk", "backup", "web", "webadmin", 
    "media", "cdn", "static", "smtp", "pop", "imap", "ns1", "ns2", "login", "auth", "payments", 
    "register", "clients", "panel", "forum", "community", "monitor", "app", "assets", 
    "mobile", "manage", "help", "adminpanel", "securemail", "beta-admin", "portaladmin", 
    "moderator", "webmaster", "root", "system", "config", "mod", "ops", "control", "files", 
    "securepanel", "myadmin", "devadmin", "dns", "config", "sysadmin", "modpanel", "staff", 
    "manager", "internal", "intranet", "controlpanel", "database", "dbadmin", "serveradmin", 
    "syslogs", "error", "dashboardadmin", "performance", "debug", "devsite", "content", 
    "resources", "fileserver", "cloud", "service", "backend", "console", "testsite", 
    "usermanager", "project", "siteadmin", "rootadmin", "securelogin", "firewall", "monitoring", 
    "files-upload", "backupadmin", "servermonitor", "systemmonitor", "appadmin", "databaselogin", 
    "control-admin", "control-root", "testserver", "webservices", "superadmin", "statusserver", 
    "sysconfig", "debugserver", "app-services", "login-admin", "sysadminportal", "root-access", 
    "errorpages", "servercontrol", "logsadmin", "phpmyadmin", "logaccess", "usermanagement", 
    "devcontrol", "serverconfig", "remoteadmin", "mailserver", "dnsserver", "loginsystem", 
    "webadminpanel", "rootlogin", "syslogs", "backupserver", "pluginadmin", "management", 
    "appcontrol", "monitoradmin", "sysadminlogin", "vpsadmin", "adminzone", "serverlogs", 
    "devcontrol", "projectcontrol", "site-manager", "mailadminpanel", "admin-home", "rootconfig", 
    "control-admin", "app-management", "hostadmin", "app-root", "metricsadmin", "securityadmin", 
    "configserver", "appportal", "remote-access", "system-logs", "rootmanager", "controlmanager", 
    "errorlog", "serverbackup", "controlsystem", "debug-access", "rootconsole", "adminaccess", 
    "secure-control", "rootsettings", "control-console", "admincloud", "filesystem", 
    "usermanagement", "emailadmin", "adminpanelzone", "appconfig", "serverops", "admin-tools", 
    "controlpaneladmin", "sysadmin-access", "error-log", "app-services-admin", "fileaccess", 
    "serverops", "control-monitor", "networkadmin", "webdashboard", "dbmanager", "adminservices"
]

# A thread worker function for scanning directories
def scan_directory(target_url, directory_queue, results, errors, delay, retries, timeout, ssl_verify, proxies):
    while not directory_queue.empty():
        directory = directory_queue.get()
        url = f"{target_url}/{directory}"
        
        attempts = 0
        while attempts < retries:
            try:
                # Randomize User-Agent and send request with optional proxies
                headers = {"User-Agent": random.choice(user_agents)}
                response = requests.get(url, headers=headers, timeout=timeout, proxies=proxies, verify=ssl_verify)
                
                # Color-coded output based on status
                if response.status_code == 200:
                    print(f"{Fore.GREEN}[FOUND] {url} | Response Time: {response.elapsed.total_seconds()} seconds")
                    results.append(url)
                    with open("found_panels.txt", "a") as log_file:
                        log_file.write(f"Found: {url}\n")
                elif "login" in response.text.lower():
                    print(f"{Fore.YELLOW}[POTENTIAL] {url} | Possible login page detected.")
                    results.append(url + " (Potential login page)")
                else:
                    print(f"{Fore.RED}[NOT FOUND] {url} | Status Code: {response.status_code}")
                break  # Exit retry loop on successful attempt

            # Handle request exceptions (e.g., timeout, connection error)
            except requests.exceptions.RequestException as e:
                print(f"{Fore.RED}[ERROR] {url} | {e}")
                errors.append(url)
                attempts += 1
                if attempts < retries:
                    print(f"{Fore.YELLOW}Retrying... ({attempts}/{retries})")
                else:
                    print(f"{Fore.RED}Max retries reached for {url}. Skipping.")
        
        # Optional delay between requests to avoid rate limiting
        time.sleep(delay)
        
        # Mark task as done in the queue
        directory_queue.task_done()

# Subdomain scanning function
def scan_subdomains(domain, results):
    print(f"{Fore.CYAN}Scanning subdomains...")
    for subdomain in common_subdomains:
        sub_url = f"http://{subdomain}.{domain}"
        try:
            headers = {"User-Agent": random.choice(user_agents)}
            response = requests.get(sub_url, headers=headers, timeout=5)
            if response.status_code == 200:
                print(f"{Fore.GREEN}[FOUND] Subdomain: {sub_url}")
                results.append(sub_url)
        except requests.exceptions.RequestException:
            pass  # Ignore errors for subdomains

def main():
    # Argument parsing for CLI options
    parser = argparse.ArgumentParser(description="Admin Panel Finder Tool")
    parser.add_argument("url", help="Target website URL (e.g., https://example.com)")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads (default: 10)")
    parser.add_argument("-d", "--delay", type=float, default=0, help="Delay between requests in seconds (default: 0)")
    parser.add_argument("-w", "--wordlist", type=str, help="Custom wordlist path for directories")
    parser.add_argument("-p", "--proxy", type=str, help="Proxy (e.g., http://10.10.1.10:3128)")
    parser.add_argument("-s", "--subdomains", action="store_true", help="Enable subdomain scanning")
    parser.add_argument("--ssl", action="store_false", help="Disable SSL verification")
    parser.add_argument("-r", "--retries", type=int, default=3, help="Number of retries for failed requests (default: 3)")
    parser.add_argument("-o", "--output", type=str, help="Save results in JSON format")
    parser.add_argument("--timeout", type=int, default=5, help="Request timeout in seconds (default: 5)")
    
    args = parser.parse_args()

    # Input validation
    target_url = args.url.strip()
    if not target_url.startswith("http"):
        print(f"{Fore.RED}Please enter a valid URL with http or https.")
        return

    # Custom or default wordlist
    if args.wordlist:
        try:
            with open(args.wordlist, 'r') as f:
                directories = [line.strip() for line in f.readlines()]
        except FileNotFoundError:
            print(f"{Fore.RED}Wordlist file not found. Using default wordlist.")
            directories = default_common_directories
    else:
        directories = default_common_directories

    # Create a queue for thread-safe directory processing
    directory_queue = Queue()
    for directory in directories:
        directory_queue.put(directory)

    # Store results and errors
    results = []
    errors = []

    # Prepare proxy settings if provided
    proxies = {"http": args.proxy, "https": args.proxy} if args.proxy else None

    # Subdomain scanning
    if args.subdomains:
        domain = target_url.replace("https://", "").replace("http://", "").split("/")[0]
        scan_subdomains(domain, results)

    # Start progress bar
    total_dirs = directory_queue.qsize()
    with tqdm(total=total_dirs, desc="Scanning Progress", colour="green") as pbar:
        # Start threads
        for _ in range(args.threads):
            worker_thread = threading.Thread(target=scan_directory, args=(target_url, directory_queue, results, errors, args.delay, args.retries, args.timeout, args.ssl, proxies))
            worker_thread.daemon = True
            worker_thread.start()

        # Update progress bar
        while not directory_queue.empty():
            time.sleep(0.1)
            pbar.n = total_dirs - directory_queue.qsize()
            pbar.refresh()

    # Wait for threads to complete
    directory_queue.join()

    # Summary
    print(f"\n{Fore.CYAN}==== Scanning Summary ====")
    print(f"{Fore.GREEN}Total panels found: {len(results)}")
    print(f"{Fore.RED}Total errors encountered: {len(errors)}")

    # Output results in JSON format if requested
    if args.output:
        with open(args.output, "w") as json_file:
            json.dump({"found": results, "errors": errors}, json_file, indent=4)
        print(f"{Fore.GREEN}Results saved to {args.output}")

    print(f"{Fore.GREEN}Scanning completed successfully.")

if __name__ == "__main__":
    # Track total time taken
    start_time = time.time()
    main()
    print(f"{Fore.GREEN}Finished in {time.time() - start_time:.2f} seconds.")

