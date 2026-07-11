"""
APEX Sensitive File Discovery
.git, .env, backups, configs, and other exposed sensitive files
"""
import requests
import concurrent.futures
from urllib.parse import urljoin


SENSITIVE_PATHS = [
    # Git
    '/.git/HEAD', '/.git/config', '/.git/index', '/.git/refs/heads/master',
    '/.git/refs/heads/main', '/.git/logs/HEAD', '/.gitignore',
    # Env files
    '/.env', '/.env.local', '/.env.production', '/.env.development',
    '/.env.backup', '/.env.example', '/.env.old', '/.env.bak',
    '/.env.staging', '/.env.test', '/.env.dev',
    # Config files
    '/wp-config.php', '/wp-config.php.bak', '/wp-config.php~', '/wp-config.php.old',
    '/wp-config.php.save', '/wp-config.php.swp', '/wp-config.txt',
    '/config.php', '/config.php.bak', '/config.php~', '/config.php.old',
    '/config.yml', '/config.yaml', '/config.json',
    '/configuration.php', '/configuration.php.bak',
    '/settings.py', '/settings.php', '/settings.json',
    '/app.config', '/web.config', '/web.config.bak', '/web.config.old',
    '/application.properties', '/application.yml', '/application.yaml',
    '/database.yml', '/database.json', '/database.ini',
    '/db.php', '/db.inc', '/db.inc.php',
    '/credentials.json', '/credentials.yml', '/credentials.ini',
    '/secrets.yml', '/secrets.json', '/secret.txt',
    # AWS/Cloud
    '/.aws/credentials', '/.aws/config',
    '/.dockercfg', '/.docker/config.json',
    '/.kube/config', '/.kube/config.yml',
    '/.terraform', '/.terraform.d',
    '/.gcloud', '/.gcp', '/.azure',
    # SSH/Keys
    '/.ssh/id_rsa', '/.ssh/id_rsa.pub', '/.ssh/id_dsa',
    '/.ssh/id_ecdsa', '/.ssh/id_ed25519', '/.ssh/authorized_keys',
    '/.ssh/known_hosts', '/id_rsa', '/id_rsa.pub',
    '/private.key', '/private.pem', '/key.pem',
    '/cert.pem', '/certificate.pem', '/fullchain.pem',
    # Backup files
    '/backup/', '/backups/', '/backup.zip', '/backup.tar.gz',
    '/backup.sql', '/backup.db', '/dump.sql', '/dump.db',
    '/database.sql', '/database.zip', '/db_backup/',
    '/site.zip', '/site.tar.gz', '/www.zip', '/www.tar.gz',
    '/backup.zip', '/backup.rar', '/backup.7z',
    '/old/', '/temp/', '/tmp/', '/cache/',
    # Log files
    '/error.log', '/error_log', '/debug.log', '/access.log',
    '/php_errors.log', '/app.log', '/application.log',
    '/server.log', '/system.log', '/syslog',
    '/logs/', '/log/', '/var/log/',
    # Package files
    '/package.json', '/package-lock.json', '/yarn.lock',
    '/composer.json', '/composer.lock',
    '/Gemfile', '/Gemfile.lock',
    '/requirements.txt', '/Pipfile', '/Pipfile.lock',
    '/Cargo.toml', '/Cargo.lock',
    '/go.mod', '/go.sum',
    '/pom.xml', '/build.gradle', '/build.gradle.kts',
    # Docker/CI
    '/Dockerfile', '/docker-compose.yml', '/docker-compose.yaml',
    '/.dockerignore', '/Dockerfile.prod', '/Dockerfile.dev',
    '/.travis.yml', '/.gitlab-ci.yml', '/.github/workflows/',
    '/Jenkinsfile', '/.circleci/config.yml',
    '/azure-pipelines.yml', '/bitbucket-pipelines.yml',
    # Other sensitive
    '/.htaccess', '/.htpasswd', '/.htpasswd.bak',
    '/phpinfo.php', '/info.php', '/test.php', '/php_info.php',
    '/adminer.php', '/adminer-4.8.1.php',
    '/server-status', '/server-info',
    '/.DS_Store', '/.svn/entries', '/.hg/store/',
    '/sitemap.xml', '/robots.txt',
    '/crossdomain.xml', '/clientaccesspolicy.xml',
    '/.well-known/security.txt',
    '/README.md', '/README.txt', '/CHANGELOG.md', '/CHANGELOG.txt',
    '/LICENSE', '/LICENSE.txt', '/LICENSE.md',
    '/Vagrantfile', '/Makefile', '/Gruntfile.js', '/Gulpfile.js',
    '/webpack.config.js', '/vite.config.js', '/rollup.config.js',
    '/tsconfig.json', '/jsconfig.json',
    '/.babelrc', '/.eslintrc', '/.prettierrc',
    '/.editorconfig', '/.stylelintrc',
    '/phpunit.xml', '/phpunit.xml.dist',
    '/.php_cs', '/.php_cs.dist',
    '/artisan', '/console', '/symfony',
    '/cron.php', '/cron.sh', '/cronjob',
    '/install.php', '/install/', '/setup.php', '/setup/',
    '/upgrade.php', '/upgrade/', '/update.php', '/update/',
    '/migrate.php', '/migration/', '/seed.php',
    '/export.php', '/import.php', '/dump.php',
    '/api.php', '/ajax.php', '/service.php',
    '/upload.php', '/uploader.php', '/fileupload.php',
    '/xmlrpc.php', '/wp-cron.php', '/wp-json/',
    '/shell.php', '/cmd.php', '/exec.php',
    '/rce.php', '/backdoor.php', '/pwn.php',
]


def discover_sensitive_files(target_url, threads=30):
    """Discover sensitive files on a target."""
    found = []
    sess = requests.Session()
    sess.verify = False
    sess.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36'
    })

    def check_path(path):
        try:
            url = urljoin(target_url, path)
            r = sess.get(url, timeout=5, allow_redirects=False)

            if r.status_code in [200, 301, 302, 401]:
                result = {
                    'url': url,
                    'status': r.status_code,
                    'size': len(r.content),
                    'type': r.headers.get('Content-Type', 'unknown'),
                    'category': 'unknown',
                }

                # Categorize
                if '.git/' in path:
                    result['category'] = 'git_exposure'
                elif '.env' in path:
                    result['category'] = 'environment_file'
                elif 'config' in path.lower() or 'wp-config' in path:
                    result['category'] = 'config_file'
                elif 'backup' in path.lower() or path.endswith(('.zip', '.tar.gz', '.sql', '.bak')):
                    result['category'] = 'backup_file'
                elif 'log' in path.lower():
                    result['category'] = 'log_file'
                elif 'key' in path.lower() or 'pem' in path or 'ssh' in path:
                    result['category'] = 'key_file'
                elif 'credential' in path.lower() or 'secret' in path.lower():
                    result['category'] = 'credential_file'
                elif 'docker' in path.lower() or 'Dockerfile' in path:
                    result['category'] = 'docker_file'
                elif path.endswith(('.json', '.lock', '.yml', '.yaml', '.xml')):
                    result['category'] = 'package_config'
                elif 'phpinfo' in path or 'info.php' in path:
                    result['category'] = 'info_disclosure'
                elif 'shell' in path or 'cmd' in path or 'backdoor' in path:
                    result['category'] = 'potential_backdoor'

                # Check content for sensitive data
                if r.status_code == 200 and len(r.content) < 50000:
                    content = r.text.lower()
                    if 'password' in content or 'passwd' in content:
                        result['sensitive_content'] = 'passwords_found'
                    if 'api_key' in content or 'apikey' in content or 'secret' in content:
                        result['sensitive_content'] = 'api_keys_found'
                    if 'jdbc:' in content or 'mysql://' in content or 'postgresql://' in content:
                        result['sensitive_content'] = 'database_url_found'
                    if '-----begin' in content and 'private key' in content:
                        result['sensitive_content'] = 'private_key_found'
                    if 'AKIA' in r.text or 'ASIA' in r.text:
                        result['sensitive_content'] = 'aws_keys_found'

                found.append(result)
        except:
            pass

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        executor.map(check_path, SENSITIVE_PATHS)

    # Sort by category priority
    category_priority = {
        'git_exposure': 0, 'environment_file': 1, 'credential_file': 2,
        'key_file': 3, 'config_file': 4, 'backup_file': 5,
        'info_disclosure': 6, 'potential_backdoor': 7, 'log_file': 8,
        'docker_file': 9, 'package_config': 10, 'unknown': 11,
    }
    found.sort(key=lambda x: category_priority.get(x.get('category', 'unknown'), 99))

    return found