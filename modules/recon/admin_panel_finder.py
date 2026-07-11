"""
APEX Admin Panel Finder
500+ paths, response fingerprinting, auto-bruteforce integration
"""
import requests
import concurrent.futures
from urllib.parse import urljoin, urlparse


# 500+ admin panel paths
ADMIN_PATHS = [
    # Generic
    '/admin', '/login', '/panel', '/dashboard', '/cpanel', '/backend',
    '/administrator', '/manage', '/management', '/control', '/cp',
    '/admin/login', '/admin/index.php', '/admin/admin.php',
    '/admin_area', '/admin_panel', '/admincp', '/adminpanel',
    '/moderator', '/moderator/login', '/moderator/admin',
    '/staff', '/staff/login', '/staff/admin',
    '/secure', '/secure/login', '/private', '/private/login',
    '/sysadmin', '/sysadmin/login', '/root', '/root/login',
    '/master', '/master/login', '/super', '/super/login',
    '/auth', '/auth/login', '/auth/admin',
    '/signin', '/sign-in', '/sign_in', '/log-in', '/log_in',
    '/account', '/account/login', '/accounts', '/accounts/login',
    '/user', '/user/login', '/users', '/users/login',
    '/member', '/member/login', '/members', '/members/login',
    '/client', '/client/login', '/clients', '/clients/login',
    '/portal', '/portal/login', '/portal/admin',
    '/site/admin', '/site/login', '/siteadmin',
    '/webadmin', '/webmaster', '/webmaster/login',
    '/config', '/configuration', '/settings', '/setup',
    '/install', '/installation', '/wizard',
    '/debug', '/test', '/dev', '/development',
    '/console', '/terminal', '/shell', '/cmd',
    '/gateway', '/gate', '/door', '/access',
    '/secret', '/hidden', '/restricted', '/lock',
    '/office', '/office/login', '/internal', '/internal/login',
    # CMS
    '/wp-admin', '/wp-admin/admin-ajax.php', '/wp-login.php',
    '/wp-admin/install.php', '/wp-admin/setup-config.php',
    '/administrator/index.php', '/administrator',
    '/user/login', '/user', '/user/register',
    '/magento/admin', '/magento/index.php/admin',
    '/admin/index.php', '/index.php/admin',
    '/shop/admin', '/shop/backend',
    '/umbraco', '/umbraco/login',
    '/concrete/index.php/login',
    '/craft/admin', '/craft/login',
    '/ghost/ghost', '/ghost/signin',
    '/processwire/admin',
    '/typo3', '/typo3/index.php',
    '/bolt/login', '/bolt/bolt',
    '/october/backend', '/october/backend/auth',
    '/statamic/cp', '/statamic/login',
    '/grav/admin', '/grav/login',
    '/kirby/panel', '/kirby/login',
    '/pagekit/admin', '/pagekit/login',
    '/pyro/admin', '/pyro/login',
    '/anchor/admin', '/anchor/login',
    '/monstra/admin', '/monstra/login',
    '/wondercms/login', '/wondercms/admin',
    '/pluck/admin', '/pluck/login',
    '/getsimple/admin', '/getsimple/login',
    '/textpattern/textpattern',
    '/serendipity_admin.php',
    '/dotclear/admin', '/dotclear/ecrire',
    '/spip/ecrire', '/spip/admin',
    '/modx/manager', '/modx/connectors',
    '/silverstripe/admin', '/silverstripe/Security/login',
    '/prestashop/admin', '/prestashop/administration',
    '/opencart/admin', '/opencart/administration',
    '/zencart/admin', '/zencart/administration',
    '/oscommerce/admin', '/oscommerce/administration',
    '/cubecart/admin', '/cubecart/admin.php',
    '/abantecart/admin', '/abantecart/index.php',
    '/cs-cart/admin', '/cs-cart/admin.php',
    '/xcart/admin', '/xcart/admin.php',
    '/shopify/admin', '/shopify/auth/login',
    '/bigcommerce/admin', '/bigcommerce/login',
    '/volusion/admin', '/volusion/login',
    '/3dcart/admin', '/3dcart/login',
    '/ecwid/admin', '/ecwid/login',
    '/squarespace/config', '/squarespace/login',
    '/wix/admin', '/wix/login',
    '/weebly/admin', '/weebly/login',
    '/jimdo/admin', '/jimdo/login',
    '/webflow/admin', '/webflow/login',
    # Database
    '/phpmyadmin', '/phpMyAdmin', '/phpmyadmin/index.php',
    '/pma', '/PMA', '/pma/index.php',
    '/mysql', '/mysql/admin', '/mysql-admin',
    '/adminer', '/adminer.php',
    '/dbadmin', '/db/admin', '/database/admin',
    '/sqladmin', '/sql/admin',
    '/myadmin', '/webdb', '/websql',
    '/pgadmin', '/pgadmin4', '/phppgadmin',
    '/mongo', '/mongoadmin', '/rockmongo',
    '/redis', '/redisadmin', '/phpredmin',
    '/memcached', '/memcache',
    '/couchdb/_utils', '/couchdb/futon',
    '/neo4j', '/neo4j/browser',
    '/orientdb', '/orientdb/studio',
    '/influxdb', '/influxdb/admin',
    '/elasticsearch', '/elasticsearch/_plugin/head',
    '/kibana', '/kibana/app/kibana',
    '/solr', '/solr/admin', '/solr/#/',
    '/rabbitmq', '/rabbitmq/#/',
    # DevOps
    '/jenkins', '/jenkins/login', '/jenkins/script',
    '/jenkins/computer', '/jenkins/manage',
    '/grafana', '/grafana/login',
    '/prometheus', '/prometheus/graph',
    '/alertmanager', '/alertmanager/#/alerts',
    '/consul', '/consul/ui',
    '/nomad', '/nomad/ui',
    '/vault', '/vault/ui',
    '/traefik', '/traefik/dashboard',
    '/portainer', '/portainer/#/auth',
    '/rancher', '/rancher/auth/login',
    '/kubernetes', '/kubernetes/dashboard',
    '/docker', '/docker/dashboard',
    '/swarm', '/swarm/dashboard',
    '/ansible', '/ansible/tower',
    '/puppet', '/puppet/dashboard',
    '/chef', '/chef/login',
    '/salt', '/salt/login',
    '/terraform', '/terraform/enterprise',
    '/gitlab', '/gitlab/users/sign_in',
    '/github', '/github/login',
    '/bitbucket', '/bitbucket/login',
    '/gitea', '/gitea/user/login',
    '/gogs', '/gogs/user/login',
    '/phabricator', '/phabricator/auth',
    '/redmine', '/redmine/login',
    '/jira', '/jira/login', '/jira/secure/Dashboard.jspa',
    '/confluence', '/confluence/login',
    '/wiki', '/wiki/admin', '/wiki/login',
    '/dokuwiki', '/dokuwiki/doku.php',
    '/mediawiki', '/mediawiki/index.php',
    '/moinmoin', '/moinmoin/admin',
    '/twiki', '/twiki/bin/view',
    '/xwiki', '/xwiki/bin/view',
    # Network
    '/router', '/switch', '/firewall', '/gateway',
    '/network', '/networking', '/netadmin',
    '/cgi-bin', '/cgi-bin/login', '/cgi-bin/admin',
    '/webmin', '/webmin/login',
    '/cpanel', '/cpanel/login',
    '/whm', '/whm/login',
    '/plesk', '/plesk/login',
    '/directadmin', '/directadmin/login',
    '/ispconfig', '/ispconfig/login',
    '/vesta', '/vesta/login',
    '/virtualmin', '/virtualmin/login',
    '/ajenti', '/ajenti/login',
    '/froxlor', '/froxlor/login',
    '/sentora', '/sentora/login',
    '/centos-webpanel', '/centos-webpanel/login',
    '/zpanel', '/zpanel/login',
    '/kloxo', '/kloxo/login',
    '/ispmanager', '/ispmanager/login',
    '/aaPanel', '/aaPanel/login',
    '/btpanel', '/btpanel/login',
    '/cockpit', '/cockpit/login',
    '/webuzo', '/webuzo/login',
    '/cloudpanel', '/cloudpanel/login',
    '/runcloud', '/runcloud/login',
    '/serverpilot', '/serverpilot/login',
    '/forge', '/forge/login',
    '/ploi', '/ploi/login',
    '/cleavr', '/cleavr/login',
    '/moss', '/moss/login',
    '/spinupwp', '/spinupwp/login',
    '/gridpane', '/gridpane/login',
    '/kinsta', '/kinsta/login',
    '/wpengine', '/wpengine/login',
    '/flywheel', '/flywheel/login',
    '/pantheon', '/pantheon/login',
    '/platformsh', '/platformsh/login',
    '/cloudways', '/cloudways/login',
    '/nexcess', '/nexcess/login',
    '/liquidweb', '/liquidweb/login',
    '/a2hosting', '/a2hosting/login',
    '/siteground', '/siteground/login',
    '/hostgator', '/hostgator/login',
    '/bluehost', '/bluehost/login',
    '/dreamhost', '/dreamhost/login',
    '/inmotion', '/inmotion/login',
    '/greengeeks', '/greengeeks/login',
    '/namecheap', '/namecheap/login',
    '/godaddy', '/godaddy/login',
    # Monitoring
    '/nagios', '/nagios/login',
    '/zabbix', '/zabbix/login',
    '/icinga', '/icinga/login',
    '/sensu', '/sensu/login',
    '/monit', '/monit/login',
    '/munin', '/munin/login',
    '/cacti', '/cacti/login',
    '/observium', '/observium/login',
    '/librenms', '/librenms/login',
    '/netdata', '/netdata/login',
    '/uptime', '/uptime/login',
    '/status', '/status/admin',
    '/health', '/health/admin',
    '/metrics', '/metrics/admin',
    '/monitor', '/monitor/login',
    '/dashboard/admin', '/dashboard/login',
    # File Managers
    '/filemanager', '/file-manager', '/files',
    '/elfinder', '/elfinder/elfinder.html',
    '/ckfinder', '/ckfinder/ckfinder.html',
    '/kcfinder', '/kcfinder/browse.php',
    '/ajaxfilemanager', '/ajaxfilemanager/ajaxfilemanager.php',
    '/tinymce', '/tinymce/filemanager',
    '/responsivefilemanager', '/responsivefilemanager/filemanager',
    '/net2ftp', '/net2ftp/index.php',
    '/extplorer', '/extplorer/index.php',
    '/kodbox', '/kodbox/index.php',
    '/filebrowser', '/filebrowser/login',
    '/cloudreve', '/cloudreve/login',
    '/nextcloud', '/nextcloud/login',
    '/owncloud', '/owncloud/login',
    '/seafile', '/seafile/login',
    '/syncthing', '/syncthing/login',
    # Other
    '/api', '/api/admin', '/api/v1/admin',
    '/graphql', '/graphiql', '/playground',
    '/swagger', '/swagger-ui.html', '/swagger/index.html',
    '/api-docs', '/api/docs', '/docs', '/redoc',
    '/actuator', '/actuator/health', '/actuator/info',
    '/actuator/env', '/actuator/mappings', '/actuator/beans',
    '/.env', '/.git/config', '/.git/HEAD',
    '/info.php', '/phpinfo.php', '/test.php',
    '/server-status', '/server-info',
    '/web-console', '/webconsole',
    '/jmx-console', '/jmx',
    '/hawtio', '/hawtio/login',
    '/camel', '/camel/login',
    '/activemq', '/activemq/admin',
    '/artemis', '/artemis/console',
    '/hornetq', '/hornetq/admin',
    '/weblogic', '/weblogic/console',
    '/websphere', '/websphere/console',
    '/jboss', '/jboss/console',
    '/wildfly', '/wildfly/console',
    '/glassfish', '/glassfish/admin',
    '/payara', '/payara/admin',
    '/resin', '/resin/admin',
    '/jetty', '/jetty/admin',
    '/tomcat', '/tomcat/manager/html', '/tomcat/manager/status',
    '/manager/html', '/manager/status', '/host-manager/html',
]


def find_admin_panels(target_url, threads=30):
    """Find admin panels on a target using multi-threaded requests."""
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

            result = {
                'url': url,
                'status': r.status_code,
                'title': '',
                'type': 'unknown',
            }

            # Extract title
            if '<title>' in r.text:
                title_start = r.text.find('<title>') + 7
                title_end = r.text.find('</title>', title_start)
                if title_end > title_start:
                    result['title'] = r.text[title_start:title_end].strip()[:100]

            # Classify the finding
            if r.status_code == 200:
                text_lower = r.text.lower()
                if any(kw in text_lower for kw in ['login', 'sign in', 'password', 'username']):
                    result['type'] = 'login_page'
                elif any(kw in text_lower for kw in ['admin', 'dashboard', 'panel', 'control']):
                    result['type'] = 'admin_panel'
                elif any(kw in text_lower for kw in ['phpmyadmin', 'mysql', 'database']):
                    result['type'] = 'database_admin'
                elif any(kw in text_lower for kw in ['jenkins', 'grafana', 'kibana']):
                    result['type'] = 'devops_tool'
                elif any(kw in text_lower for kw in ['swagger', 'api', 'openapi']):
                    result['type'] = 'api_docs'
                elif any(kw in text_lower for kw in ['cpanel', 'whm', 'plesk', 'webmin']):
                    result['type'] = 'hosting_panel'
                elif any(kw in text_lower for kw in ['file', 'upload', 'browse']):
                    result['type'] = 'file_manager'
                else:
                    result['type'] = 'accessible'
                found.append(result)
            elif r.status_code == 401:
                result['type'] = 'auth_required'
                found.append(result)
            elif r.status_code == 403:
                result['type'] = 'forbidden'
                found.append(result)
            elif r.status_code in [301, 302]:
                location = r.headers.get('Location', '')
                if 'login' in location.lower() or 'admin' in location.lower():
                    result['type'] = 'redirect_to_login'
                    found.append(result)

        except requests.exceptions.Timeout:
            pass
        except:
            pass

    # Use thread pool for speed
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        executor.map(check_path, ADMIN_PATHS)

    # Sort by type priority
    type_priority = {
        'admin_panel': 0, 'login_page': 1, 'database_admin': 2,
        'devops_tool': 3, 'hosting_panel': 4, 'file_manager': 5,
        'api_docs': 6, 'auth_required': 7, 'redirect_to_login': 8,
        'forbidden': 9, 'accessible': 10, 'unknown': 11,
    }
    found.sort(key=lambda x: type_priority.get(x['type'], 99))

    return found


def get_default_credentials(panel_type):
    """Get default credentials for common admin panels."""
    defaults = {
        'phpmyadmin': [('root', ''), ('root', 'root'), ('admin', 'admin'), ('admin', '')],
        'tomcat': [('tomcat', 'tomcat'), ('admin', 'admin'), ('tomcat', 's3cret')],
        'jenkins': [('admin', 'admin'), ('jenkins', 'jenkins'), ('admin', 'password')],
        'grafana': [('admin', 'admin'), ('admin', 'grafana')],
        'wordpress': [('admin', 'admin'), ('admin', 'password'), ('admin', '123456')],
        'joomla': [('admin', 'admin'), ('admin', 'joomla')],
        'drupal': [('admin', 'admin'), ('admin', 'drupal')],
        'magento': [('admin', 'admin123'), ('admin', 'password')],
        'cpanel': [('root', 'root'), ('admin', 'admin')],
        'webmin': [('root', 'root'), ('admin', 'admin')],
    }
    return defaults.get(panel_type, [('admin', 'admin'), ('admin', 'password'), ('admin', '123456')])