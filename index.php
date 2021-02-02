<?php

// get the path i want to save session file
define('SESSION_SAVE_PATH', dirname(realpath(__FILE__)) . DIRECTORY_SEPARATOR . 'sessions');

class AppSessionHandler extends SessionHandler {

	private $sessionName = 'MYAPPSESS';
	private $sessionMaxLifeTime = 0;
	private $sessionSSL = false;
	private $sessionHTTPOnly = true;
	private $sessionPath = '/';
	private $sessionDomain = '.mydomain.test';
	private $sessionSavePath = SESSION_SAVE_PATH;

	// Mcrypt ciphers 
	private $sessionCipherAlgo = MCRYPT_BLOWFISH;
	private $sessionCipherMode = MCRYPT_MODE_ECB;
	private $sessionCipherKey = 'WYCRYPT0K3Y2020';

	// time i want to regenerate new session by minute here
	private $ttl = 30;


	public function __construct() {

		ini_set('session.use_cookies', 1);
		ini_set('session.use_only_cookies', 1);
		ini_set('session.use_trans_sid', 0);
		ini_set('session.save_handler', 'files');
	
		session_name($this->sessionName);
		session_save_path($this->sessionSavePath);

		session_set_cookie_params(
			$this->sessionMaxLifeTime, $this->sessionPath,
			$this->sessionDomain, $this->sessionSSL,
			$this->sessionHTTPOnly
		);

		// this mean the object have the control to use session
		session_set_save_handler($this, true);
	}


	public function __get($key) {
		return false !== $_SESSION[$key] ? $_SESSION[$key] : false;
	}

	public function __set($key, $value) {
		$_SESSION[$key] = $value;
	}

	public function __isset($key) {
		return isset($_SESSION[$key]) ? true : false;
	}

	// Descrypt data 
	public function read($id) {
		return mcrypt_decrypt($this->sessionCipherAlgo, $this->sessionCipherKey, parent::read($id), $this->sessionCipherMode);
	}

	// Encrypt data when i wrting session
	public function write($id, $data) {
		return parent::write($id, mcrypt_encrypt($this->sessionCipherAlgo, $this->sessionCipherKey, $data, $this->sessionCipherMode));
	}


	// this method to start session
	public function start() {
		// if there's no session make one
		if ('' === session_id()) {
			if (session_start()) {
				$this->setSessionStartTime();
				$this->checkSessionValidity();
			}
		}
	}

	private function setSessionStartTime() {
		if (!isset($this->sessionStartTime)) {
			$this->sessionStartTime = time();
		}
		return true;
	}

	private function checkSessionValidity() {
		if ((time() - $this->sessionStartTime) > ($this->ttl * 60)) {
			$this->renewSession();
			$this->generateFingerPrint();
		}
		return true;
	}

	private function renewSession() {
		$this->sessionStartTime = time();
		return session_regenerate_id(true);
	}

	// the method to kill session when i write $session->killSession
	public function killSession() {
		
		// unset session from data
		session_unset();

		// set another cookie with the same value and negattive time to delete it
		setcookie(
				$this->sessionName, '',  time() - 1000,
				$this->sessionPath, $this->sessionDomain,
				$this->sessionSSL, $this->sessionHTTPOnly
		);

		// and here we go : destory session after unset and delete the cookie
		session_destroy();

	}

	private function generateFingerPrint() {
		// get the header http user agent 
		$userAgent = $_SERVER['HTTP_USER_AGENT'];
		// generate random cipher key from 16 number
		$this->cipherKey = mcrypt_create_iv(16);
		// set session id 
		$sessionId = session_id();
		// combine all this and encoding them
		$this->fingerPrint = md5($userAgent . $this->cipherKey . $sessionId);
	}


	// check if the real user login again the site or another one want to trick session
	// the method prevent session fixation 
	public function isValidFingerPrint() {
		if (!isset($this->fingerPrint)) {
			$this->generateFingerPrint();	
		}

		$fingerPrint = md5($_SERVER['HTTP_USER_AGENT'] . $this->cipherKey . session_id());

		if ($fingerPrint === $this->fingerPrint) {
			return true;
		}
		return false;

	}

}

$session = new AppSessionHandler();
// start the session
$session->start();

if (!$session->isValidFingerPrint()) {
	$session->killSession();
}

// To maintain session when redirect to another page
// use relative path better than absolute path  (/session.php better than http://www.mydomain.php/session.php)
//better why to fix probelm losing  data in session this below code :)

// session_write_close();
// header('Location: /session.php');
// exit();