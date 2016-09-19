<?php
/*
Plugin Name: SLW Firewall 
Plugin URI: http://alicomez.com/
Description: Wordpress siteler için yapılandırılmış SLW firewall
Author: Slaweally
Version: 1.00
Author URI: http://alicomez.com/
*/ 

if(!function_exists('array_diff_key')){
    if ((@include_once 'PHP/Compat/Function/array_diff_key.php')) {}
	else{   	
	// Borrowed from PEAR_PHP_Compat.	
	function php_compat_array_diff_key()
	{
	    $args = func_get_args();
	    if (count($args) < 2) {
	        user_error('Wrong parameter count for array_diff_key()', E_USER_WARNING);
	        return;
	    }
	    // Check arrays
	    $array_count = count($args);
	    for ($i = 0; $i !== $array_count; $i++) {
	        if (!is_array($args[$i])) {
	            user_error('array_diff_key() Argument #' .
	                ($i + 1) . ' is not an array', E_USER_WARNING);
	            return;
	        }
	    }
	    $result = $args[0];
	    if (function_exists('array_key_exists')) {
	        // Optimize for >= PHP 4.1.0
	        foreach ($args[0] as $key => $value) {
	            for ($i = 1; $i !== $array_count; $i++) {
	                if (array_key_exists($key,$args[$i])) {
	                    unset($result[$key]);
	                    break;
	                }
	            }
	        }
	    } else {
	        foreach ($args[0] as $key1 => $value1) {
	            for ($i = 1; $i !== $array_count; $i++) {
	                foreach ($args[$i] as $key2 => $value2) {
	                    if ((string) $key1 === (string) $key2) {
	                        unset($result[$key2]);
	                        break 2;
	                    }
	                }
	            }
	        }
	    }
	    return $result; 
	}		
	    function array_diff_key()
	    {
	        $args = func_get_args();
	        return call_user_func_array('php_compat_array_diff_key', $args);
	    }
	}
}

if(preg_match("#^wordpress-firewall.php#", basename($_SERVER['PHP_SELF']))) exit();

add_option('WP_firewall_redirect_page', 'homepage');
add_option('WP_firewall_exclude_directory', 'allow');
add_option('WP_firewall_exclude_queries', 'allow');
add_option('WP_firewall_exclude_terms', 'allow');
add_option('WP_firewall_exclude_spaces', 'allow');
add_option('WP_firewall_exclude_file', 'allow');
add_option('WP_firewall_exclude_http', 'disallow');
add_option('WP_firewall_email_enable','enable');
add_option('WP_firewall_email_address', get_option('admin_email'));
add_option('WP_firewall_whitelisted_ip', '');
add_option('WP_firewall_whitelisted_page', '');
add_option('WP_firewall_whitelisted_variable', '');
add_option('WP_firewall_plugin_url', get_option('siteurl') 
.'/wp-admin/options-general.php?page=' . basename(__FILE__));
add_option('default_WP_firewall_whitelisted_page', 
serialize(array( array('.*/wp-comments-post\.php',array('url', 'comment')),
array('.*/wp-admin/.*',array( '_wp_original_http_referer','_wp_http_referer' 
)),
array('.*wp-login.php', array('redirect_to')),
array('.*', array('comment_author_url_.*', '__utmz', )),
'.*/wp-admin/options-general\.php', '.*/wp-admin/post-new\.php', 
'.*/wp-admin/page-new\.php','.*/wp-admin/link-add\.php', '.*/wp-admin/post\.php',
'.*/wp-admin/page\.php',
'.*/wp-admin/admin-ajax.php')));
add_option('WP_firewall_previous_attack_var', '');
add_option('WP_firewall_previous_attack_ip', '');
add_option('WP_firewall_email_limit', 'off');

WP_firewall_check_exclusions ();

function WP_firewall_check_exclusions () {

	$request_string = WP_firewall_check_whitelisted_variable();
	if($request_string == false){
	} else{
		if(get_option('WP_firewall_exclude_directory') == 'allow'){
			
			$exclude_terms = array('#etc/passwd#', '#proc/self/environ#', '#\.\./#');
			foreach($exclude_terms as $preg){
				foreach($request_string as $key=>$value){
					if(preg_match($preg, $value)){
						if(!WP_firewall_check_ip_whitelist()){	
							WP_firewall_send_log_message($key, $value, 
							'directory-traversal-attack', 'Directory Traversal');			
							WP_firewall_send_redirect();
						}	
					}		
				}	
			}
		}
		if(get_option('WP_firewall_exclude_queries') == 'allow'){	
			$exclude_terms = array('#concat\s*\(#i', '#group_concat#i',
			'#union.*select#i');
			foreach($exclude_terms as $preg){
				foreach($request_string as $key=>$value){	
					if(preg_match($preg, $value) ){
						if(!WP_firewall_check_ip_whitelist()){	
							WP_firewall_send_log_message($key, $value, 
							'sql-injection-attack', 'SQL Injection');			
							WP_firewall_send_redirect();
						}
					}
				}
			}	
		}
		if(get_option('WP_firewall_exclude_terms') == 'allow'){
			$exclude_terms = array('#wp_#i', '#user_login#i', 
			'#user_pass#i', '#0x[0-9a-f][0-9a-f]#i', '#/\*\*/#');
		
			foreach($exclude_terms as $preg){
				foreach($request_string as $key=>$value){					
					if(preg_match($preg, $value)){
						if(!WP_firewall_check_ip_whitelist()){					
							WP_firewall_send_log_message($key, $value, 
							'wp-specific-sql-injection-attack', 'WordPress-Specific SQL Injection');
							WP_firewall_send_redirect();
						}
					}
				}
			}
		}	
		if(get_option('WP_firewall_exclude_spaces') == 'allow'){	
			$exclude_terms = array('#\s{49,}#i','#\x00#');
			foreach($exclude_terms as $preg){
				foreach($request_string as $key=>$value){					
					if(preg_match('#\s{49,}#i', $value) ){
						if(!WP_firewall_check_ip_whitelist()){				
							WP_firewall_send_log_message($key, $value, 
							'field-truncation-attack', 'Field Truncation');
							WP_firewall_send_redirect();
						}		
					}
				}
			}
		}
		if(get_option('WP_firewall_exclude_file') == 'allow'){	
			foreach ($_FILES as $file) {
				$file_extensions = 
				array('#\.dll$#i', '#\.rb$#i', '#\.py$#i',
				'#\.exe$#i', '#\.php[3-6]?$#i','#\.pl$#i', 
				'#\.perl$#i', '#\.ph[34]$#i', '#\.phl$#i' ,
				'#\.phtml$#i', '#\.phtm$#i');
				 foreach($file_extensions as $regex){
					if(preg_match($regex, $file['name'])){
				 		WP_firewall_send_log_message('$_FILE', $file['name'], 
				 		'executable-file-upload-attack', 'Executable File Upload');
						WP_firewall_send_redirect();	
					}	
				 }
			}			
		}			
		if(get_option('WP_firewall_exclude_http') == 'allow'){	
			
			$exclude_terms = array('#^http#i', '#\.shtml#i');
			foreach($exclude_terms as $preg){			
			
				foreach($request_string as $key=>$value){				
					if(preg_match($preg, $value)){
						if(!WP_firewall_check_ip_whitelist()){				
							WP_firewall_send_log_message($key, $value, 
							'remote-file-execution-attack', 'Remote File Execution');
							WP_firewall_send_redirect();
						}		
					}
				}
			}
		}		
	}
}

function WP_firewall_send_redirect(){
	$home_url = get_option('siteurl');	
	if(get_option('WP_firewall_redirect_page') == '404page'){
		// Not clear if just including the 404 template is safe.
		header ("Location: $home_url/404/");
		exit();
	}
	else {
		header ("Location: $home_url");
		exit();		
	}
}

function WP_firewall_check_whitelisted_variable(){
	
	preg_match('#([^?]+)?.*$#',$_SERVER['REQUEST_URI'], $url);	
	$page_name = $url[1];	

	$_a = array();
	$new_arr = WP_firewall_array_flatten($_REQUEST, $_a);

	foreach(
	unserialize(get_option('default_WP_firewall_whitelisted_page'))
	as $whitelisted_page){											

		if(!is_array($whitelisted_page)){
			if(preg_match('#^' . $whitelisted_page . '$#',$page_name)){
				return false;
			}
		}else{
			if(preg_match('#^' . $whitelisted_page[0] . '$#',$page_name)){
				foreach($whitelisted_page[1] as $whitelisted_variable){
					foreach(array_keys($new_arr) as $var){	
						if(preg_match('#^' . $whitelisted_variable 
						.'$#',$var)){	
							$new_arr = array_diff_key($new_arr,array($var=>''));	
						}
					}
				}
			}			
		}
	}
	
	$pages     = unserialize(
	get_option('WP_firewall_whitelisted_page'));
	$variables = unserialize(
	get_option('WP_firewall_whitelisted_variable'));
	$count = 0;
	
	while($count < sizeof($pages)){
		
		$page_regex =  preg_quote($pages[$count], '#') ;
		$page_regex = str_replace('\*', '.*', $page_regex);		
		
		$var_regex =  preg_quote($variables[$count], '#') ;
		$var_regex = str_replace('\*', '.*', $var_regex);	
		
		if( $variables[$count] != ''){
			if($pages[$count] == '' || preg_match('#^' . $page_regex . '$#',
			$page_name)){
				$temp_arr = $new_arr;
				foreach(array_keys($new_arr) as $var){
					if(preg_match('#^' . $var_regex . '$#',$var)){
						$new_arr = array_diff_key($new_arr,array($var=>''));	
					}
				}
			}				
		} elseif($pages[$count] != ''){
			if(	preg_match('#^' . $page_regex . '$#',$page_name)){
				return false;
			}
		}		
		$count++;
	}					
	return $new_arr;
}

function GetIP(){
    if(getenv("HTTP_CLIENT_IP")) {
         $ip = getenv("HTTP_CLIENT_IP");
     } elseif(getenv("HTTP_X_FORWARDED_FOR")) {
         $ip = getenv("HTTP_X_FORWARDED_FOR");
         if (strstr($ip, ',')) {
             $tmp = explode (',', $ip);
             $ip = trim($tmp[0]);
         }
     } else {
     $ip = getenv("REMOTE_ADDR");
     }
    return $ip;
}

function WP_firewall_send_log_message($bad_variable = '',
$bad_value = '', $attack_type = '', $attack_category = ''){
	
	$bad_variable = htmlentities($bad_variable);
	$bad_value = htmlentities($bad_value);
	
	$offender_ip = GetIP();

	$limit_check = (
	get_option('WP_firewall_email_limit') == 'on' 
	&&  $offender_ip == get_option('WP_firewall_previous_attack_ip')
	&&  $bad_variable == get_option('WP_firewall_previous_attack_var')
	);
			
	if( $address = get_option('WP_firewall_email_address')&& !$limit_check
	){
		$suppress_message = (get_option('WP_firewall_email_limit')=='on')
		?
		'Benzer saldırılar için Tekrarlanan uyarılar şu anda e-posta yoluyla gönderilir, 
		<a href="' . get_option('WP_firewall_plugin_url')  . 
		'&suppress=0">Tıkla</a> ve bastır.'
		: '';
		
		
		$offending_url = $_SERVER['HTTP_HOST'] .$_SERVER['REQUEST_URI'] ;
		
		
		$variable_explain_url   = 
		'http://alicomez.com/slw-firewall.slw'
		. $attack_type;

		$turn_off_email_url 	= get_option('WP_firewall_plugin_url') 
		.'&turn_off_email=1';
		$whitelist_varibale_url = get_option('WP_firewall_plugin_url') 
		. '&set_whitelist_variable=' . $bad_variable ;
			
		$message =<<<EndMessage
		<h3>SLW Firewall <font color="red">tespit ve bloke et</font> 
		potansiyel bir saldırı olabilir!</h3>
		<table border="0" cellpadding="5">
		<tr>
		<td align="right"><b>Web sayfası:&nbsp;&nbsp;</b></td>
		<td>$offending_url <br />
		<small>Uyarı: &nbsp; URL tehlikeli içeriğe sahip olabilir!</small>
		</td>
		</tr>
		<tr>
		<td align="right"><b>Soruna neden olan IP:&nbsp;&nbsp;</b></td>
		<td>$offender_ip
	<a href="http://whatismyipaddress.com/ip/$offender_ip">
		[ İp Lokasyonuna bakın ]
		</a>
		</td>
		</tr>
		<tr>
		<td align="right">
		<b>Sorun parametresi:&nbsp;&nbsp;</b>
		</td>
		<td><font color="red"><b> $bad_variable = $bad_value </b></font></td>
		</tr>
		</table>
		<br />
		<table>
		<tr>
		<td align="left"> 
		"$attack_category Bu atak olabilir"<br /><br />Bilgi için 
		<a href="$variable_explain_url">Tıkla</a> Bu bir yanlış alarm olabilir. eğer bu uyarının yanlış olduğunu düşünüyorsanız beyazliste ip'lerine ekleyin bir sonraki seferde bunu önemsemeyeceğiz.
		<br /><br />
		<a href="$whitelist_varibale_url">Tıkla</a> Beyaz listee işle
		<br /> 
		<a href="$turn_off_email_url ">tıkla</a> Bu e-postaları kapatın.
		</td>
		<tr>
		<td>$suppress_message</td>
		</tr>
		</table>
		<br />
			 
		<div style="float:right; position:relative; top:-80px;">
		<a 
	href="http://alicomez.com/slw-firewall.slw" 
		style="text-decoration:none;" target="_blank">
		<img src=
	"http://alicomez.com/wp-content/uploads/2014/11/logo1.png"
		border="0" />
		<br />
		<small>Firewall hakkında</small>
		</a>
		<br />
		<small>Geri bildirim Gönder
		<a style="text-decoration:none;" href=
		"http://alicomez.com/slw-firewall.slw"
		target="_blank">Click here.</a>
		</small>
		<br />
		<small>Destek ol
		<a style="text-decoration:none;" 
		href="http://alicomez.com/slw-firewall.slw"
		target="_blank">this simple disclaimer.
		</a>
		</small>	
		</div>
		
EndMessage;
	
		$address = get_option('WP_firewall_email_address');
		$subject = 'WP Firewall Bilgi !! ' 
		. get_option('siteurl');
		$header = "Content-Type: text/html\r\n";		
		$header .= "Konu: " . $address . "\r\n";		
		mail($address,$subject,$message, $header);
	}
	
	update_option('WP_firewall_previous_attack_var', $bad_variable);
	update_option('WP_firewall_previous_attack_ip', $offender_ip);
}

function WP_firewall_check_ip_whitelist(){
	$current_ip = $_SERVER['REMOTE_ADDR'];
	$ips = unserialize(get_option('WP_firewall_whitelisted_ip'));
	if(is_array($ips)){
		foreach($ips as $ip){
			if( $current_ip == $ip || $current_ip == gethostbyname($ip)){
				return true;
			}
		}
	}
	return false;
}

function WP_firewall_array_flatten($array, &$newArray, 
	$prefix='',$delimiter='][',  $level = 0) {
	foreach ($array as $key => $child) {
		if (is_array($child)) {
			$newPrefix = $prefix.$key.$delimiter;
			if($level==0){$newPrefix=$key.'[';}
			$newArray =& WP_firewall_array_flatten($child, $newArray, 
			$newPrefix, $delimiter, $level+1);
		} else {
			(!$level) ?$post='' : $post=']';
			$newArray[$prefix.$key. $post] = $child;
		}
	}
	return $newArray;
} 

function WP_firewall_assert_first(){
	$active_plugs = (get_option('active_plugins'));
	$active_plugs = array_diff($active_plugs, array("wordpress-firewall.php"));
	array_unshift($active_plugs, "wordpress-firewall.php");	
}
add_action('admin_menu', 'WP_firewall_admin_menu');

function WP_firewall_admin_menu() {
	add_submenu_page('options-general.php','SLW Firewall',
	'SLW Firewall', 10, __FILE__, 'WP_firewall_submenu');
}

function WP_firewall_submenu(){
	
	WP_firewall_assert_first();
	
	$action_url = $_SERVER['REQUEST_URI'];
	if ($_REQUEST['set_exclusions']){
		update_option('WP_firewall_redirect_page',
		$_REQUEST['redirect_type']);					
		update_option('WP_firewall_exclude_directory', 
		$_REQUEST['block_directory']);
		update_option('WP_firewall_exclude_queries', 
		$_REQUEST['block_queries']);
		update_option('WP_firewall_exclude_terms', 
		$_REQUEST['block_terms']);
		update_option('WP_firewall_exclude_spaces', 
		$_REQUEST['block_spaces']);
		update_option('WP_firewall_exclude_file', 
		$_REQUEST['block_file']);		
		update_option('WP_firewall_exclude_http', 
		$_REQUEST['block_http']);
		
		echo '<div class="updated fade">
		<p>Güvenlik Filtreler ve Yönlendirme sayfası güncellendi.</p>
		</div>';		
	} elseif($_REQUEST['turn_off_email']){
		
		update_option('WP_firewall_email_address', '');
		
		$action_url = str_replace('&turn_off_email=1','',
		$_SERVER['REQUEST_URI']);
		echo '<div class="updated fade">
		<p>E-postalar artık kapatılır.</p>
		</div>';		
	
	} elseif($_REQUEST['set_whitelist_variable']){
		echo '<div class="updated fade"><p>bEYAZ LİSTE '
		. $_REQUEST['set_whitelist_variable'] .'</p></div>';

		$pages       = unserialize(
		get_option('WP_firewall_whitelisted_page'));
		$variables 	 = unserialize(
		get_option('WP_firewall_whitelisted_variable'));	
		$pages[]   	 = '';
		$variables[] =	$_REQUEST['set_whitelist_variable'];

		update_option('WP_firewall_whitelisted_page', serialize($pages));
		update_option('WP_firewall_whitelisted_variable', 
		serialize($variables));		
		
		$action_url = str_replace(('&set_whitelist_variable=' . 
		$_REQUEST['set_whitelist_variable']),'',$_SERVER['REQUEST_URI']);
		echo '<div class="updated fade">
		<p>beyazliste ip güncellendi</p>
		</div>';
		
	} elseif($_REQUEST['set_email']){
		update_option('WP_firewall_email_address', 
		$_REQUEST['email_address']);
		update_option('WP_firewall_email_limit', 
		$_REQUEST['email_limit']);	
		echo '<div class="updated fade">
		<p>Email güncellendi</p>
		</div>';		
	} elseif($_REQUEST['set_whitelist_ip']){
		update_option('WP_firewall_whitelisted_ip', 
		serialize($_REQUEST['whitelisted_ip']));
		echo '<div class="updated fade">
		<p>İp listesi Güncellendi</p>
		</div>';		
	} elseif($_REQUEST['set_whitelist_page']){
		update_option('WP_firewall_whitelisted_page', 
		serialize($_REQUEST['whitelist_page']));
		update_option('WP_firewall_whitelisted_variable',
		serialize($_REQUEST['whitelist_variable']));
		echo '<div class="updated fade">
		<p>Beyazliste sayfalar güncellendi</p>
		</div>';		
	} elseif($_REQUEST['suppress'] === '0'){
		
		update_option('WP_firewall_email_limit', 'off');
		echo '<div class="updated fade">
		<p>Email güncellendi</p>
		</div>';		
		$action_url = str_replace('&suppress=0','',
		$_SERVER['REQUEST_URI']);		
	}

	?> 
	<div class="wrap" style="background-color:#cae1ff; border:1px solid red; ">
	<div style="background-color:#87cefa; border:1px solid red; " align="center">	
		<h1><b>SLW Firewall Ayarlar</b></h1>
	</div>
	<form name="set-exclusion-options" action="<?php echo $action_url; ?>" 
	method="post" >
	<div style="background-color:#fffafa; border:1px solid red; " align="center">
	<h3>Güvenlik Filtreleri:</h3>
	<input type="checkbox" value="allow" name="block_directory" 
	<?php echo (get_option('WP_firewall_exclude_directory') == 'allow')
	?'checked="checked"':''?>
	> Dizinler arası geçişi kapatılsın mı (../, ../../etc/passwd, etc.)<br />
	<input type="checkbox" value="allow" name="block_queries" 
	<?php echo (get_option('WP_firewall_exclude_queries') == 'allow') 
	? 'checked="checked"' :''?>
	> SQL sorguları filtrelenip bloklansın mı (union select, concat(, /**/, etc.)<br />
	<input type="checkbox" value="allow" name="block_terms" 
	<?php echo (get_option('WP_firewall_exclude_terms') == 'allow') 
	? 'checked="checked"' :''?>
	> WP Özel terimleri bloklansın mı (wp_, user_login, etc.) 
	<br />
	<input type="checkbox" value="allow" name="block_spaces" 
	<?php echo (get_option('WP_firewall_exclude_spaces') == 'allow') 
	? 'checked="checked"' :''?>
	> DDos Botnet atan ipneler bloklansın mı <br />
	
	
	<input type="checkbox" value="allow" name="block_file" 
	<?php echo (get_option('WP_firewall_exclude_file') == 'allow') 
	? 'checked="checked"' :''?>
	> Upload edilen dosya türleri bloklansın mı (.php, .exe, etc.)<br />

	
	
	<input type="checkbox" value="allow" name="block_http" 
	<?php echo (get_option('WP_firewall_exclude_http') == 'allow') 
	? 'checked="checked"' :''?>
	>Güvenli bağlantı sağlansın mı ? http:// yi https:// yapar ancak birçok eklenti ile uyumsuz olduğundan bu özelliği kullanmanız Önerilmez !!!.<br />
	
	
	<h3>Saldırı Tespit edilirse ne yapılsın ?</h3>	
	<table class="form-table" border="0" 
	style="width:500px; margin-top:0; margin-bottom:1px;" >
	<tr>
	<td>404 Hata sayfasına yönlendir </td>
	<td><input type="radio" name="redirect_type" value="404page"  
	<?php echo (get_option('WP_firewall_redirect_page') == '404page') 
	? 'checked="checked"' :''?> > 
	</td></tr>
	<tr>
	<td>Anasayfaya yönlendir </td>
	<td><input type="radio" name="redirect_type" value="homepage"  
	<?php echo (get_option('WP_firewall_redirect_page') == 'homepage') 
	? 'checked="checked"' :''?> >
	</td></tr>
	</table>	
	
	<small><b>Note:</b> Not: Tüm filtreler "Beyaz Liste IP'leri" ve aşağıdaki "Beyaz Listeye Sayfalar" tabidir.
	below.</small><br /><br />
	
	<input type="submit" name="set_exclusions" value="Güvenlik filtrelerini uygula">
	</form>	
	
	<h3>Saldırı bildirisi için Email:</h3>
	Saldırı veya herhangi bir durumda için bildiri göndermemiz için email girin :<br /><br />
	<form name="email_address" action="<?php echo $action_url; ?>" 
	method="post" >
	<input type="text" value="<?php echo get_option('WP_firewall_email_address')?>"
	name="email_address" ><br />
	<small><b>Note:</b> E-posta bildirimini devre dışı bırakmak için boş Bu ayarı bırakın.</small>
	<br /><br />	
	Benzer bir saldırı uyarısı e-postaları
	
	<input type="radio" name="email_limit" value="on"
	<?php echo (get_option('WP_firewall_email_limit') == 'on') ? 
	'checked="checked"' :''?>>
	Açık
	
	<input type="radio" name="email_limit" value="off"
	<?php echo (get_option('WP_firewall_email_limit') == 'off') ? 
	'checked="checked"' :''?>>
	Kapalı

	<br /><br />
	<input type="submit" name="set_email" value="Ayarı Kaydet">
	
	</form>
	</div>
	<h3>Beyaz Liste  IP:</h3>
	Güvendiğiniz ip Listesini girin.
	
	<br /><br />
	<form name="whitelist_ip" action="<?php echo $action_url;?>" method="post">
	<?php
	if( !get_option('WP_firewall_whitelisted_ip')){
		echo '<input type="text" value="" name="whitelisted_ip[]" >
		<br /><br />';	
	} else{
		$ips = array_unique(unserialize(get_option('WP_firewall_whitelisted_ip')));
		foreach($ips as $ip){
			if($ip != ''){
				echo  '<input type="text" value="' .$ip 
				. '" name="whitelisted_ip[]" ><br />';	
			}		
		}
		echo  '<input type="text" value="" name="whitelisted_ip[]" ><br />';	
	}
	?>
	<small><b>Not:</b> Boş bırakılırsa sizin ip adresinizi baz alır
	Kendi ip Adresiniz: <b><?php echo $_SERVER['REMOTE_ADDR']?></b>.</small>
	<br /><br />
	<input type="submit" name="set_whitelist_ip" value="İp ayarlarını kaydet">
	</form>
<br><br>
	<?php
	WP_firewall_show_plugin_link();
	echo '</div>';
}

function WP_firewall_show_plugin_link(){
	?>
	<div style="float:right; position:relative; top:-70px;">
	<a href="http://alicomez.com/slw-firewall.slw"
     style="text-decoration:none;" target="_blank">
	<?php
	if(preg_match('#MSIE#', $_SERVER['HTTP_USER_AGENT']) == 0) {
	?>
	<img src="http://alicomez.com/wp-content/uploads/2014/11/logo1.png" />
	<?php } ?>
	<br />
	<small>Firewall Hakkında</small>
	</a>
	<br />
	<small>Geri Bildirim 
	<a style="text-decoration:none;" 
	href=
"http://alicomez.com/slw-firewall.slw"
	target="_blank">
	Tıklayın
	</a>
	</small>	
	<br />	
	</div>
	<?php
}
?>
