<?php
// Offline test with in-memory WordPress meta stubs (no WordPress, no DB).
putenv('MO2F_BRIDGE_SELFTEST=1');
$META = array();
function get_user_meta($u,$k,$s=true){ global $META; return isset($META[$u][$k]) ? $META[$u][$k] : ''; }
function update_user_meta($u,$k,$v){ global $META; $META[$u][$k]=$v; return true; }
function delete_user_meta($u,$k){ global $META; if(isset($META[$u][$k])){unset($META[$u][$k]);return true;} return false; }
require '/s/mo2f-ga-secret-bridge.php';
// encrypt exactly like Mo2f_GAuth_AESEncryption::encrypt_data_ga (6.6.0)
function enc_ga($d,$k){$c='AES-128-CBC';$iv=openssl_random_pseudo_bytes(openssl_cipher_iv_length($c));$r=openssl_encrypt($d,$c,$k,OPENSSL_RAW_DATA,$iv);return base64_encode($iv.hash_hmac('sha256',$r,$k,true).$r);}
$S='JBSWY3DPEHPK3PXP';
$META[1]=array('mo2f_gauth_key'=>enc_ga($S,'aB3dE6gH'),'mo2f_get_auth_rnd_string'=>'aB3dE6gH');
$META[2]=array('mo2f_gauth_key'=>enc_ga($S,'aB3dE6gH'),'mo2f_get_auth_rnd_string'=>'WRONGKEY');
$META[3]=array();
$META[4]=array('mo2f_gauth_key'=>enc_ga($S,'k'),'mo2f_get_auth_rnd_string'=>'k','mo2f_secret_ga'=>'ENC:EXISTING');
$t=function($n,$c){echo ($c?'PASS ':'FAIL ').$n."\n";};
ob_start(); $rc=mo2f_bridge_user(1,'--dry-run'); ob_end_clean(); $t('dry run rc0 + nothing written', $rc===0 && get_user_meta(1,'mo2f_secret_ga')==='');
ob_start(); $rc=mo2f_bridge_user(1,'--write'); $o=ob_get_clean(); $t('write sets the exact old secret', $rc===0 && get_user_meta(1,'mo2f_secret_ga')===$S && strpos($o,$S)===false);
$t('old keys untouched', get_user_meta(1,'mo2f_get_auth_rnd_string')==='aB3dE6gH' && get_user_meta(1,'mo2f_gauth_key')!=='');
ob_start(); $rc=mo2f_bridge_user(1,'--write'); ob_end_clean(); $t('second write = no-op', $rc===0 && get_user_meta(1,'mo2f_secret_ga')===$S);
ob_start(); $rc=mo2f_bridge_user(2,'--write'); ob_end_clean(); $t('wrong key -> stop, nothing written', $rc===4 && get_user_meta(2,'mo2f_secret_ga')==='');
ob_start(); $rc=mo2f_bridge_user(3,'--write'); ob_end_clean(); $t('no old secret -> skip', $rc===3);
ob_start(); $rc=mo2f_bridge_user(4,'--write'); ob_end_clean(); $t('existing new secret never overwritten', get_user_meta(4,'mo2f_secret_ga')==='ENC:EXISTING');
ob_start(); $rc=mo2f_bridge_user(1,'--undo'); ob_end_clean(); $t('undo deletes only mo2f_secret_ga', get_user_meta(1,'mo2f_secret_ga')==='' && get_user_meta(1,'mo2f_gauth_key')!=='');
