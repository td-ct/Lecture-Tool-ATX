<?php
declare(strict_types=1);
/* ============================================================
   Lecture Tool ATX (ATX = Attention Tracker) — single-file PHP app
   ------------------------------------------------------------
   - Aufruf ohne Parameter        -> Dozenten-Ansicht
   - Aufruf mit ?s=SESSIONID      -> Studenten-Ansicht
   - ?api=stream&s=ID             -> SSE-Live-Stream (Push)
   - ?api=snapshot&s=ID           -> JSON-Snapshot (Fallback)
   - POST (JSON)                  -> Aktionen: create / start / stop / toggle / join / leave
                                     / list / export / delete
   (Restart ist rein lokal: die Session-Datei bleibt als Archiv erhalten.)
   Speicherung: zzz-data/sess_<ID>.json (automatisch angelegt, parallel zum Skript).
   Die Daten liegen damit unabhängig von der Dozenten-Ansicht dauerhaft auf dem Server.
   Dozenten-Identität: pro Session gespeicherter, mit der Session-ID gesalzener
   SHA-256-Hash des Passworts. Das Passwort selbst wird nie gespeichert.
   Verschlüsselung: Session-Dateien liegen als AES-256-GCM-Chiffre vor (Daten-
   schlüssel doppelt gewickelt: unter dem Passwort und unter .masterkey).
   ============================================================ */

$DATA_DIR = __DIR__ . '/zzz-data';
if (!is_dir($DATA_DIR)) { @mkdir($DATA_DIR, 0770, true); }

function sid_ok(string $s): bool { return (bool)preg_match('/^[A-Za-z0-9]{4,12}$/', $s); }
function spath(string $s): string { global $DATA_DIR; return $DATA_DIR . '/sess_' . $s . '.json'; }

/* ---- Verschlüsselung der Session-Dateien (AES-256-GCM) ----
   Jede Datei hat einen zufälligen Daten-Schlüssel F, doppelt eingewickelt:
   - 'km': F unter dem Server-Master-Key (zzz-data/.masterkey), damit auch
     Studenten-Eingaben (ohne Passwort) gespeichert werden können, und
   - 'kp': F unter dem Passwort-Schlüssel (Owner-Hash), damit das Passwort
     tatsächlich an der Verschlüsselung beteiligt ist.
   Ohne openssl-Extension: Klartext-Fallback (Altbestand bleibt lesbar). */
function master_key(): string {
    global $DATA_DIR;
    $f = $DATA_DIR . '/.masterkey';
    if (is_file($f)) return (string)file_get_contents($f);
    $k = bin2hex(random_bytes(32));
    file_put_contents($f, $k, LOCK_EX);
    @chmod($f, 0600);
    return $k;
}
function crypto_ok(): bool { return function_exists('openssl_encrypt'); }
function wrap($plain, $key32) {
    $n = random_bytes(12); $t = '';
    $c = openssl_encrypt($plain, 'aes-256-gcm', $key32, OPENSSL_RAW_DATA, $n, $t);
    return ['n'=>base64_encode($n), 'c'=>base64_encode($c), 't'=>base64_encode($t)];
}
function unwrap(array $h, $key32) {
    $n = base64_decode((string)$h['n']); $t = base64_decode((string)$h['t']);
    $p = openssl_decrypt(base64_decode((string)$h['c']), 'aes-256-gcm', $key32, OPENSSL_RAW_DATA, $n, $t);
    return ($p === false) ? null : $p;
}
function load_sess(string $s): ?array {
    $p = spath($s);
    if (!is_file($p)) return null;
    $raw = json_decode((string)file_get_contents($p), true);
    if (!is_array($raw)) return null;
    if (isset($raw['id'])) return $raw;               // Klartext (Fallback / Altbestand)
    if (!crypto_ok() || !isset($raw['km'], $raw['v'])) return null;
    $f = unwrap($raw['km'], hash('sha256', master_key(), true));
    if ($f === null) return null;
    $plain = unwrap($raw['v'], $f);
    if ($plain === null) return null;
    $d = json_decode($plain, true);
    return is_array($d) ? $d : null;
}
function save_sess(string $s, array $d): void {
    $d['rev'] = ($d['rev'] ?? 0) + 1;
    $plain = json_encode($d, JSON_UNESCAPED_UNICODE);
    $p = spath($s);
    if (!crypto_ok()) { file_put_contents($p, $plain, LOCK_EX); return; }
    /* Daten-Schlüssel F aus bestehender Datei übernehmen oder neu erzeugen */
    $f = null;
    if (is_file($p)) {
        $hdr = json_decode((string)file_get_contents($p), true);
        if (is_array($hdr) && isset($hdr['km'])) $f = unwrap($hdr['km'], hash('sha256', master_key(), true));
    }
    if ($f === null || $f === '') $f = random_bytes(32);
    $out = [
        'km' => wrap($f, hash('sha256', master_key(), true)),   // Server-Master-Wrap
        'v'  => wrap($plain, $f),                               // eigentliche Nutzdaten
    ];
    if (isset($d['owner']) && is_string($d['owner'])) {
        $out['kp'] = wrap($f, hash('sha256', hex2bin($d['owner']), true)); // Passwort-Wrap
    }
    file_put_contents($p, json_encode($out), LOCK_EX);
}
function new_sid(): string {
    $c = 'abcdefghjkmnpqrstuvwxyz23456789';
    $s = ''; for ($i=0;$i<6;$i++) $s .= $c[random_int(0, strlen($c)-1)];
    return $s;
}

/* Dozenten-Passwort: pro Session salted Hash, Klartext nie speichern */
function owner_hash(string $pw, string $sid): string { return hash('sha256', $sid . '|' . $pw); }
function owner_ok(array $d, string $s, string $pw): bool {
    return isset($d['owner']) && hash_equals($d['owner'], owner_hash($pw, $s));
}

/* Fallback, falls die mbstring-Erweiterung fehlt (waere sonst ein fatal error
   mitten im list/claim-Ablauf); E-Mails sind ASCII, strtolower genuegt hier */
if (!function_exists('mb_strtolower')) {
    function mb_strtolower(string $s, $enc = null): string { return strtolower($s); }
}

/* Text kürzen ohne mbstring-Abhängigkeit */
function ucut(string $s, int $max): string {
    $s = trim($s);
    if ($s === '') return '';
    if (function_exists('mb_substr')) return mb_substr($s, 0, $max);
    preg_match('/^.{0,' . $max . '}/us', $s, $m);
    return $m[0] ?? '';
}

/* Automatisches Ende: spätestens 6 h nach Ablauf der geplanten Zeit,
   falls der Dozent nicht selbst auf Stop drückt */
function autostop(string $s): void {
    sess_mutate($s, function (array &$d) {
        if (empty($d['started_at']) || !empty($d['stopped_at'])) return ['save' => false];
        $limit = (int)$d['started_at'] + (int)($d['planned_min'] ?? 0) * 60 + 21600;
        if (time() > $limit) { $d['stopped_at'] = $limit; $d['stop_by'] = 'auto'; return ['save' => true]; }
        return ['save' => false];
    });
}

/* Kritische Abschnitte: exklusive Datei-Sperre pro Session, damit gleichzeitige
   Zugriffe (z. B. zwei Studenten öffnen zeitgleich den QR-Link) sich nicht
   gegenseitig überschreiben. Laden, Ändern und Speichern passieren unter einem Lock. */
function sess_mutate(string $s, callable $fn): array {
    $h = @fopen(spath($s) . '.lock', 'c');
    if ($h) flock($h, LOCK_EX);
    try {
        $d = load_sess($s);
        if (!$d) return ['code' => 404, 'body' => ['ok' => false, 'error' => 'session not found']];
        $res = $fn($d) ?: [];
        if (!empty($res['save'])) save_sess($s, $d);
        unset($res['save']);
        return $res;
    } finally {
        if ($h) { flock($h, LOCK_UN); fclose($h); }
    }
}
function reply(array $res): void {
    if (isset($res['code'])) http_response_code($res['code']);
    echo json_encode($res['body'] ?? ['ok' => true]);
    exit;
}

/* Status-Abfrage-Modus: 'start' = Startzustand je Checkbox, Studenten
   entscheiden sonst selbst; 'auto' = automatische Runden alle warn_min Minuten;
   'ondemand' = Dozent fragt über „Prüfen“ gezielt ab, davor sind alle undef.
   Alt-Sessions ohne Feld verhalten sich wie bisher (warn_min > 0 -> auto). */
function ask_mode_of(array $d): string {
    $m = (string)($d['ask_mode'] ?? '');
    if (in_array($m, ['start', 'auto', 'ondemand'], true)) return $m;
    return ((int)($d['warn_min'] ?? 0) > 0) ? 'auto' : 'start';
}
/* Startzustand beim Beitritt je Modus (Alt-Sessions: wie früher nach start_in) */
function join_state_of(array $d): string {
    return (ask_mode_of($d) === 'start' && !empty($d['start_in'])) ? 'in' : 'undef';
}

/* Neuentscheidung öffnen: alle Studenten haben ab jetzt 60 s, um sich neu für
   IN/OUT zu entscheiden; danach rutschen Unentschlossene auf "undef". */
function open_decide(array &$d, string $by, int $now): void {
    $d['decide_seq'] = (int)($d['decide_seq'] ?? 0) + 1;
    $d['decide_until'] = $now + 60;
    $cnt = ['in'=>0,'out'=>0,'undef'=>0];
    foreach (($d['students'] ?? []) as $st) { $cur = $st['st'] ?? 'undef'; if (isset($cnt[$cur])) $cnt[$cur]++; }
    $d['events'][] = ['t'=>$now, 's'=>'', 'kind'=>'warn', 'msg'=>'', 'emoji'=>'', 'val'=>0, 'by'=>$by, 'cnt'=>$cnt];
}

/* Abstimmungspakete: Bloecke durch Leerzeilen getrennt; Zeile 1 = Ueberschrift,
   darunter je Zeile eine Option (Titel + mindestens eine Option noetig) */
function parse_vote_packs(string $raw): array {
    $packs = []; $block = [];
    foreach (preg_split('/\r\n|\r|\n/', $raw) as $ln) {
        $t = trim($ln);
        if ($t === '') { if ($block) { $packs[] = $block; $block = []; } continue; }
        $block[] = $t;
    }
    if ($block) $packs[] = $block;
    $out = [];
    foreach ($packs as $b) {
        if (count($b) < 2) continue;
        $out[] = ['title' => ucut($b[0], 120), 'opts' => array_map(fn($o) => ucut($o, 120), array_slice($b, 1, 10))];
    }
    return $out;
}

/* Bewertungsfragen: Frage-Zeile, darunter eine Zeile mit den Optionen,
   getrennt durch |. Endet die Optionszeile auf |c, gibt es zusaetzlich
   ein freies Textfeld. Blöcke = Frage + Optionszeile (Leerzeilen beliebig). */
function parse_eval_qs(string $raw): array {
    $lines = [];
    foreach (preg_split('/\r\n|\r|\n/', $raw) as $ln) { $t = trim($ln); if ($t !== '') $lines[] = $t; }
    $qs = [];
    for ($i = 0; $i + 1 < count($lines); $i += 2) {
        $q = ucut($lines[$i], 200);
        $optLine = $lines[$i + 1];
        $cmt = false;
        if (preg_match('/\|\s*c$/i', $optLine)) { $cmt = true; $optLine = preg_replace('/\|\s*c$/i', '', $optLine); }
        $opts = array_values(array_filter(array_map('trim', explode('|', $optLine)), fn($x) => $x !== ''));
        $opts = array_slice(array_map(fn($o) => ucut($o, 200), $opts), 0, 10); // max. 10 Optionen je Frage
        if ($q !== '' && ($opts || $cmt)) $qs[] = ['q' => $q, 'opts' => $opts, 'cmt' => $cmt];
    }
    return $qs;
}

/* Abstimmung abschließen: Stimmen der laufenden Runde zählen, Ergebnis als
   voteclose-Ereignis dokumentieren. $mode: 'auto' = Zeit abgelaufen,
   'all' = alle haben gewählt, 'manual' = Dozent hat beendet. */
function close_vote(array &$d, int $now, string $mode): bool {
    if (empty($d['vote_until'])) return false;
    $round = (int)($d['vote_no'] ?? 0);
    $pack = (int)($d['vote_pack'] ?? 0);
    $votes = [];
    foreach (($d['events'] ?? []) as $e) {
        if (($e['kind'] ?? '') === 'vote' && (int)($e['round'] ?? -1) === $round)
            $votes[(int)$e['val']] = ($votes[(int)$e['val']] ?? 0) + 1;
    }
    ksort($votes);
    /* Beteiligung dokumentieren: gewählt haben / anwesend */
    $voters = [];
    foreach (($d['events'] ?? []) as $e)
        if (($e['kind'] ?? '') === 'vote' && (int)($e['round'] ?? -1) === $round)
            $voters[$e['s']] = 1;
    $d['events'][] = ['t'=>$now, 's'=>'', 'kind'=>'voteclose', 'msg'=>'', 'emoji'=>'', 'val'=>0,
        'round'=>$round, 'votes'=>$votes, 'mode'=>$mode, 'pack'=>$pack,
        'voters'=>count($voters), 'present'=>count($d['students'] ?? [])];
    $d['vote_until'] = 0;
    $d['vote_pack'] = 0;
    return true;
}

/* Folgezustände: automatische Warnung nach X Minuten, Ablauf der Neuentscheidung
   (IN/OUT -> undef) und Abschluss der Abstimmung mit Ergebnis. */
function advance_state(string $s): void {
    sess_mutate($s, function (array &$d) {
        $now = time();
        if (!empty($d['stopped_at'])) return ['save' => false];
        $save = false;
        /* automatische Neuentscheidung alle warn_min Minuten — nur im Modus 'auto' */
        $anchor = (int)($d['sched_start'] ?? 0) ?: (int)($d['started_at'] ?? 0);
        $warnMin = (int)($d['warn_min'] ?? 0);
        $rounds = (int)($d['warn_rounds'] ?? 0);
        if (ask_mode_of($d) === 'auto' && $warnMin > 0 && $anchor && $now - $anchor >= $warnMin * 60 * ($rounds + 1)) {
            $d['warn_rounds'] = $rounds + 1;
            open_decide($d, 'auto', $now);
            $save = true;
        }
        /* Ablauf der Neuentscheidung: Unentschlossene -> undef, Ergebnis dokumentieren */
        if (!empty($d['decide_until']) && $now > (int)$d['decide_until']) {
            $seq = (int)($d['decide_seq'] ?? 0);
            $before = ['in'=>0,'out'=>0,'undef'=>0];
            foreach (($d['students'] ?? []) as $tok => $st) { $cur = $st['st'] ?? 'undef'; if (isset($before[$cur])) $before[$cur]++; }
            foreach (($d['students'] ?? []) as $tok => $st) {
                if ((int)($st['seq'] ?? 0) < $seq && in_array($st['st'] ?? '', ['in','out'], true)) {
                    $d['students'][$tok]['st'] = 'undef';
                    $d['events'][] = ['t'=>$now, 's'=>$tok, 'kind'=>'undef', 'msg'=>'', 'emoji'=>'', 'val'=>0];
                }
            }
            $after = ['in'=>0,'out'=>0,'undef'=>0];
            foreach (($d['students'] ?? []) as $st) { $cur = $st['st'] ?? 'undef'; if (isset($after[$cur])) $after[$cur]++; }
            $d['events'][] = ['t'=>$now, 's'=>'', 'kind'=>'decided', 'msg'=>'', 'emoji'=>'', 'val'=>0,
                'cnt'=>['in'=>$before['in'],'out'=>$before['out'],'undef'=>$before['undef'],
                         'in2'=>$after['in'],'out2'=>$after['out'],'undef2'=>$after['undef']]];
            $d['decide_until'] = 0;
            $save = true;
        }
        /* Ablauf der Abstimmung: Stimmen zählen und Ergebnis dokumentieren */
        if (!empty($d['vote_until']) && $now > (int)$d['vote_until']) {
            $save = close_vote($d, $now, 'auto') || $save;
        }
        return ['save' => $save];
    });
}

/* ---------------- POST-API ---------------- */
if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
    header('Content-Type: application/json; charset=utf-8');
    $in = json_decode((string)file_get_contents('php://input'), true) ?: [];
    $action = $in['action'] ?? '';
    /* Sprache der Server-Meldungen: der Client meldet sie mit (GET-Fallback) */
    $lang = (($in['lang'] ?? ($_GET['lang'] ?? 'de')) === 'en') ? 'en' : 'de';
    function emsg(string $de, string $en): string { global $lang; return $lang === 'en' ? $en : $de; }

    if ($action === 'create') {
        $pw = (string)($in['pw'] ?? '');
        if (strlen($pw) < 4) { http_response_code(400); echo json_encode(['ok'=>false,'error'=>emsg('Bitte ein Dozenten-Passwort (mind. 4 Zeichen) wählen','Please choose a lecturer password (min. 4 characters)')]); exit; }
        $min = max(5, min(720, (int)($in['planned_min'] ?? 90)));
        $title = ucut((string)($in['title'] ?? ''), 120);
        $lect  = ucut((string)($in['lecturer'] ?? ''), 80);
        $mail  = ucut((string)($in['email'] ?? ''), 100);
        $inst  = ucut((string)($in['institute'] ?? ''), 120);
        $sched_start = (int)($in['sched_start'] ?? 0);
        $sched_end   = (int)($in['sched_end'] ?? 0);
        $start_in    = !empty($in['start_in']);               // Studenten starten direkt IN
        $warn_min    = max(0, min(240, (int)($in['warn_min'] ?? 0))); // 0 = keine Auto-Neuentscheidung
        $ask_mode    = (string)($in['ask_mode'] ?? 'ondemand');       // Status-Abfrage-Modus
        if (!in_array($ask_mode, ['start', 'auto', 'ondemand'], true)) $ask_mode = 'ondemand';
        if ($ask_mode === 'ondemand') { $start_in = false; $warn_min = 0; } // alle undef bis zur ersten „Prüfen“-Abfrage
        elseif ($ask_mode === 'auto') {   $start_in = false; }              // undef bis zur Abfrage direkt zum Start
        else {                           $start_in = true; $warn_min = 0; } // 'start': Start IN, Selbstmeldung, keine Runden
        if ($sched_start < 0 || $sched_end < 0 || ($sched_start && $sched_end && $sched_end <= $sched_start)) {
            http_response_code(400); echo json_encode(['ok'=>false,'error'=>emsg('Ungültige geplante Zeiten','Invalid scheduled times')]); exit;
        }
        $s = new_sid();
        save_sess($s, [
            'id' => $s,
            'title' => $title,
            'lecturer' => $lect,
            'email' => $mail,
            'institute' => $inst,
            'sched_start' => $sched_start,
            'sched_end' => $sched_end,
            'started_at' => null, // Vorlesung startet erst mit 'start'
            'planned_min' => $min,
            'start_in' => $start_in,
            'ask_mode' => $ask_mode,
            'warn_min' => $warn_min,
            'decide_seq' => 0,
            'decide_until' => 0,
            'vote_no' => 0,
            'vote_until' => 0,
            'vote_pack' => 0,
            'vote_packs' => parse_vote_packs((string)($in['vote_packs'] ?? '')),
            'eval_qs' => parse_eval_qs((string)($in['evalq'] ?? '')),
            'owner' => owner_hash($pw, $s),
            'students' => [],
            'events' => [],
        ]);
        if (!is_file(spath($s))) {
            http_response_code(500);
            echo json_encode(['ok'=>false,'error'=>emsg('zzz-data-Ordner nicht beschreibbar (www-data, chmod 770)','zzz-data folder not writable (www-data, chmod 770)')]);
            exit;
        }
        echo json_encode(['ok'=>true,'id'=>$s]); exit;
    }

    if ($action === 'start') {
        $s = (string)($in['s'] ?? '');
        if (!sid_ok($s)) { http_response_code(400); echo json_encode(['ok'=>false,'error'=>'bad session']); exit; }
        $pw = (string)($in['pw'] ?? '');
        reply(sess_mutate($s, function (array &$d) use ($s, $pw) {
            if (!owner_ok($d, $s, $pw)) return ['code' => 403, 'body' => ['ok'=>false,'error'=>emsg('falsches Passwort','wrong password')]];
            if (!empty($d['stopped_at'])) return ['code' => 409, 'body' => ['ok'=>false,'error'=>emsg('Vorlesung ist bereits beendet','Lecture is already finished')]];
            if (empty($d['started_at'])) {
                $d['started_at'] = time();
                /* erwartetes Ende fest mitprotokollieren */
                $d['expected_end'] = time() + (int)($d['planned_min']) * 60;
                /* Modus 'auto': direkt zu Beginn einmal abfragen (60 s),
                   danach läuft das eingestellte Intervall bis zur nächsten Abfrage */
                if (ask_mode_of($d) === 'auto')
                    open_decide($d, 'auto', time());
                return ['save' => true, 'body' => ['ok'=>true]];
            }
            return ['body' => ['ok'=>true]];
        }));
    }

    if ($action === 'stop') {
        $s = (string)($in['s'] ?? '');
        if (!sid_ok($s)) { http_response_code(400); echo json_encode(['ok'=>false,'error'=>'bad session']); exit; }
        $pw = (string)($in['pw'] ?? '');
        reply(sess_mutate($s, function (array &$d) use ($s, $pw) {
            if (!owner_ok($d, $s, $pw)) return ['code' => 403, 'body' => ['ok'=>false,'error'=>emsg('falsches Passwort','wrong password')]];
            if (empty($d['started_at'])) return ['code' => 409, 'body' => ['ok'=>false,'error'=>emsg('Vorlesung wurde noch nicht gestartet','Lecture has not been started yet')]];
            if (empty($d['stopped_at'])) {
                $d['stopped_at'] = time(); $d['stop_by'] = 'lecturer'; // Aufzeichnung endet hier
                return ['save' => true, 'body' => ['ok'=>true]];
            }
            return ['body' => ['ok'=>true]];
        }));
    }

    if ($action === 'toggle') {
        $s = (string)($in['s'] ?? '');
        if (!sid_ok($s)) { http_response_code(400); echo json_encode(['ok'=>false,'error'=>'bad session']); exit; }
        $token = (string)($in['token'] ?? '');
        if (!preg_match('/^[A-Za-z0-9\-]{8,40}$/', $token)) { http_response_code(400); echo json_encode(['ok'=>false,'error'=>'bad token']); exit; }
        $state = ($in['state'] === 'out') ? 'out' : 'in';
        $msg   = ucut((string)($in['msg'] ?? ''), 300);
        $emoji = ucut((string)($in['emoji'] ?? ''), 40);
        /* optionale Foliennummer: nur gesetzt, wenn der Student sie gewählt hat */
        $slide = (isset($in['slide']) && $in['slide'] !== null && $in['slide'] !== '')
            ? max(1, min(999, (int)$in['slide'])) : 0;
        /* Eingaben sind ab QR-Registrierung jederzeit erlaubt;
           nur nach dem Stopp des Dozenten ist die Aufzeichnung geschlossen */
        reply(sess_mutate($s, function (array &$d) use ($token, $state, $msg, $emoji, $slide) {
            if (!empty($d['stopped_at'])) return ['code' => 410, 'body' => ['ok'=>false,'error'=>'finished']];
            /* On-demand-Modus: IN/OUT nur während einer „Prüfen“-Abfrage möglich */
            if (ask_mode_of($d) === 'ondemand'
                && (empty($d['decide_until']) || time() > (int)$d['decide_until']))
                return ['code' => 409, 'body' => ['ok'=>false,'error'=>emsg('Gerade keine Abfrage aktiv — der Dozent fragt gezielt ab','No status poll active right now — the lecturer asks on demand')]];
            if (!isset($d['students'][$token]))
                $d['students'][$token] = ['joined' => time(), 'st' => $state, 'seq' => (int)($d['decide_seq'] ?? 0)];
            else {
                $d['students'][$token]['st'] = $state;
                $d['students'][$token]['seq'] = (int)($d['decide_seq'] ?? 0); // Neuentscheidung erfüllt
            }
            $d['events'][] = ['t' => time(), 's' => $token, 'kind' => $state, 'msg' => $msg,
                'emoji' => $emoji, 'val' => 0, 'slide' => $slide];
            return ['save' => true, 'body' => ['ok'=>true, 'slide' => $slide]];
        }));
    }

    if ($action === 'join') {
        $s = (string)($in['s'] ?? '');
        if (!sid_ok($s)) { http_response_code(400); echo json_encode(['ok'=>false,'error'=>'bad session']); exit; }
        $token = (string)($in['token'] ?? '');
        if (!preg_match('/^[A-Za-z0-9\-]{8,40}$/', $token)) { http_response_code(400); echo json_encode(['ok'=>false,'error'=>'bad token']); exit; }
        reply(sess_mutate($s, function (array &$d) use ($token) {
            if (!empty($d['stopped_at'])) return ['code' => 410, 'body' => ['ok'=>false,'error'=>'finished']];
            if (isset($d['students'][$token])) return ['body' => ['ok'=>true,'joined'=>false]];
            $d['students'][$token] = ['joined' => time(),
                'st' => join_state_of($d),   // Startzustand je Modus
                'seq' => 0, 'vote' => null];
            $d['events'][] = ['t' => time(), 's' => $token, 'kind' => 'join', 'msg' => '', 'emoji' => '', 'val' => 0];
            return ['save' => true, 'body' => ['ok'=>true,'joined'=>true]];
        }));
    }

    if ($action === 'leave') {
        $s = (string)($in['s'] ?? '');
        if (!sid_ok($s)) { http_response_code(400); echo json_encode(['ok'=>false,'error'=>'bad session']); exit; }
        $token = (string)($in['token'] ?? '');
        reply(sess_mutate($s, function (array &$d) use ($token) {
            if (!empty($d['stopped_at']) || !isset($d['students'][$token])) return ['body' => ['ok'=>true]];
            unset($d['students'][$token]);
            $d['events'][] = ['t' => time(), 's' => $token, 'kind' => 'leave', 'msg' => '', 'emoji' => ''];
            return ['save' => true, 'body' => ['ok'=>true]];
        }));
    }

    if ($action === 'test') {
        /* Dozent fordert alle Studenten zur Neuentscheidung auf (60 s), jederzeit */
        $s = (string)($in['s'] ?? '');
        if (!sid_ok($s)) { http_response_code(400); echo json_encode(['ok'=>false,'error'=>'bad session']); exit; }
        $pw = (string)($in['pw'] ?? '');
        reply(sess_mutate($s, function (array &$d) use ($s, $pw) {
            if (!owner_ok($d, $s, $pw)) return ['code' => 403, 'body' => ['ok'=>false,'error'=>emsg('falsches Passwort','wrong password')]];
            if (!empty($d['stopped_at'])) return ['code' => 409, 'body' => ['ok'=>false,'error'=>emsg('Vorlesung ist bereits beendet','Lecture is already finished')]];
            open_decide($d, 'lecturer', time());
            return ['save' => true, 'body' => ['ok'=>true]];
        }));
    }

    if ($action === 'vote') {
        /* Dozent eröffnet eine 60-Sekunden-Abstimmung: Ziffern 1–9 (0 = Enthaltung)
           oder ein zuvor hinterlegtes Optionspaket (Titel + Optionen) */
        $s = (string)($in['s'] ?? '');
        if (!sid_ok($s)) { http_response_code(400); echo json_encode(['ok'=>false,'error'=>'bad session']); exit; }
        $pw = (string)($in['pw'] ?? '');
        $pack = max(0, (int)($in['pack'] ?? 0));
        reply(sess_mutate($s, function (array &$d) use ($s, $pw, $pack) {
            if (!owner_ok($d, $s, $pw)) return ['code' => 403, 'body' => ['ok'=>false,'error'=>emsg('falsches Passwort','wrong password')]];
            if (!empty($d['stopped_at'])) return ['code' => 409, 'body' => ['ok'=>false,'error'=>emsg('Vorlesung ist bereits beendet','Lecture is already finished')]];
            if ($pack > 0 && !isset(($d['vote_packs'] ?? [])[$pack - 1]))
                return ['code' => 400, 'body' => ['ok'=>false,'error'=>emsg('unbekanntes Optionspaket','unknown vote package')]];
            $d['vote_no'] = (int)($d['vote_no'] ?? 0) + 1;
            $d['vote_pack'] = $pack;
            $d['vote_until'] = time() + 60;
            $d['events'][] = ['t'=>time(), 's'=>'', 'kind'=>'voteopen', 'msg'=>'', 'emoji'=>'', 'val'=>0,
                'round'=>(int)$d['vote_no'], 'pack'=>$pack];
            return ['save' => true, 'body' => ['ok'=>true, 'round'=>(int)$d['vote_no']]];
        }));
    }

    if ($action === 'voteext') {
        /* Dozent verlängert die laufende Abstimmung um eine Minute */
        $s = (string)($in['s'] ?? '');
        if (!sid_ok($s)) { http_response_code(400); echo json_encode(['ok'=>false,'error'=>'bad session']); exit; }
        $pw = (string)($in['pw'] ?? '');
        reply(sess_mutate($s, function (array &$d) use ($s, $pw) {
            if (!owner_ok($d, $s, $pw)) return ['code' => 403, 'body' => ['ok'=>false,'error'=>emsg('falsches Passwort','wrong password')]];
            if (empty($d['vote_until']) || time() > (int)$d['vote_until'])
                return ['code' => 409, 'body' => ['ok'=>false,'error'=>emsg('keine laufende Abstimmung','no active vote')]];
            $d['vote_until'] = (int)$d['vote_until'] + 60;
            return ['save' => true, 'body' => ['ok'=>true, 'until'=>(int)$d['vote_until']]];
        }));
    }

    if ($action === 'votestop') {
        /* Dozent beendet die Abstimmung sofort; Ergebnis wird dokumentiert */
        $s = (string)($in['s'] ?? '');
        if (!sid_ok($s)) { http_response_code(400); echo json_encode(['ok'=>false,'error'=>'bad session']); exit; }
        $pw = (string)($in['pw'] ?? '');
        reply(sess_mutate($s, function (array &$d) use ($s, $pw) {
            if (!owner_ok($d, $s, $pw)) return ['code' => 403, 'body' => ['ok'=>false,'error'=>emsg('falsches Passwort','wrong password')]];
            if (empty($d['vote_until']))
                return ['code' => 409, 'body' => ['ok'=>false,'error'=>emsg('keine laufende Abstimmung','no active vote')]];
            close_vote($d, time(), 'manual');
            return ['save' => true, 'body' => ['ok'=>true]];
        }));
    }

    if ($action === 'eval') {
        /* Student beantwortet eine Bewertungsfrage — erst nach dem Stopp möglich.
           Je Frage genau eine Antwort, Option + optionaler Freitext. */
        $s = (string)($in['s'] ?? '');
        if (!sid_ok($s)) { http_response_code(400); echo json_encode(['ok'=>false,'error'=>'bad session']); exit; }
        $token = (string)($in['token'] ?? '');
        if (!preg_match('/^[A-Za-z0-9\-]{8,40}$/', $token)) { http_response_code(400); echo json_encode(['ok'=>false,'error'=>'bad token']); exit; }
        $qi = (int)($in['q'] ?? -1);
        $ans = ucut((string)($in['a'] ?? ''), 200);
        $cmt = ucut((string)($in['c'] ?? ''), 300);
        reply(sess_mutate($s, function (array &$d) use ($token, $qi, $ans, $cmt) {
            if (empty($d['stopped_at']))
                return ['code' => 409, 'body' => ['ok'=>false,'error'=>emsg('Bewertung erst nach Ende der Vorlesung','evaluation only after the lecture ended')]];
            /* Bewertungsfrist: bis zu 24 Stunden nach Ende der Vorlesung */
            if (time() > (int)$d['stopped_at'] + 86400)
                return ['code' => 410, 'body' => ['ok'=>false,'error'=>emsg('Die Bewertungsfrist von 24 Stunden ist abgelaufen','The 24-hour evaluation deadline has passed')]];
            $q = ($d['eval_qs'] ?? [])[$qi] ?? null;
            if (!$q) return ['code' => 404, 'body' => ['ok'=>false,'error'=>'bad question']];
            if (!empty($q['opts'])) {
                if (!in_array($ans, $q['opts'], true))
                    return ['code' => 400, 'body' => ['ok'=>false,'error'=>'bad option']];
            } else {
                /* reine Kommentarfrage („|c“ ohne Optionen): Freitext ist die Antwort */
                if ($ans !== '' || $cmt === '')
                    return ['code' => 400, 'body' => ['ok'=>false,'error'=>'comment required']];
            }
            if (!isset($d['students'][$token]))
                /* Student hat die Vorlesung verlassen: Eintrag mit left-Flag wieder
                   anlegen, damit die Bewertung (je Frage genau eine Antwort) auch
                   nach dem Verlassen innerhalb der 24-h-Frist möglich bleibt */
                $d['students'][$token] = ['joined'=>time(), 'st'=>'undef', 'seq'=>0, 'left'=>true];
            $done = $d['students'][$token]['eval_done'] ?? [];
            if (!empty($done[$qi]))
                return ['code' => 409, 'body' => ['ok'=>false,'error'=>'already answered']];
            $done[$qi] = 1;
            $d['students'][$token]['eval_done'] = $done;
            $d['events'][] = ['t'=>time(), 's'=>$token, 'kind'=>'eval', 'msg'=>(empty($q['cmt']) ? '' : $cmt),
                'emoji'=>'', 'val'=>0, 'q'=>$qi, 'qq'=>$q['q'], 'a'=>$ans];
            return ['save' => true, 'body' => ['ok'=>true]];
        }));
    }

    if ($action === 'cast') {
        /* Student stimmt in der laufenden Runde ab (frei: 0 = Enthaltung, 1–9;
           Optionspaket: 1..Anzahl Optionen); letzte Stimme zählt */
        $s = (string)($in['s'] ?? '');
        if (!sid_ok($s)) { http_response_code(400); echo json_encode(['ok'=>false,'error'=>'bad session']); exit; }
        $token = (string)($in['token'] ?? '');
        if (!preg_match('/^[A-Za-z0-9\-]{8,40}$/', $token)) { http_response_code(400); echo json_encode(['ok'=>false,'error'=>'bad token']); exit; }
        $val = (int)($in['val'] ?? 0); /* Wertebereich wird je Abstimmungstyp geprüft */
        reply(sess_mutate($s, function (array &$d) use ($token, $val, $in) {
            if (empty($d['vote_until']) || time() > (int)$d['vote_until'])
                return ['code' => 410, 'body' => ['ok'=>false,'error'=>'vote finished']];
            /* Wertebereich: frei 0-10, Optionspaket 1..Anzahl Optionen */
            $packIdx = (int)($d['vote_pack'] ?? 0);
            if ($packIdx > 0) {
                $opts = ($d['vote_packs'] ?? [])[$packIdx - 1]['opts'] ?? [];
                if ($val < 1 || $val > count($opts))
                    return ['code' => 400, 'body' => ['ok'=>false,'error'=>'bad option']];
            } else {
                $val = max(0, min(10, $val));
            }
            $round = (int)($d['vote_no'] ?? 0);
            if (!isset($d['students'][$token]))
                $d['students'][$token] = ['joined'=>time(), 'st'=>join_state_of($d), 'seq'=>0, 'vote'=>$val];
            else $d['students'][$token]['vote'] = $val;
            foreach (($d['events'] ?? []) as $i => $e) {  // frühere Stimme derselben Runde ersetzen
                if (($e['kind'] ?? '') === 'vote' && ($e['s'] ?? '') === $token && (int)($e['round'] ?? -1) === $round)
                    unset($d['events'][$i]);
            }
            $d['events'] = array_values($d['events']);
            $d['events'][] = ['t'=>time(), 's'=>$token, 'kind'=>'vote', 'msg'=>'', 'emoji'=>'', 'val'=>$val, 'round'=>$round];
            /* direktes Absenden: Student hat fertig, ohne auf das Zeitende zu warten.
               Er bleibt für "alle haben abgestimmt" und die Auszählung vollständig erfasst. */
            if (!empty($in['confirm']))
                $d['students'][$token]['vote_done'] = $round;
            /* vorzeitig schließen, sobald alle anwesenden Studenten gewählt haben
               (verworfene, "left"-Studenten zählen nicht als anwesend) */
            $voted = [];
            foreach (($d['events'] ?? []) as $e)
                if (($e['kind'] ?? '') === 'vote' && (int)($e['round'] ?? -1) === $round)
                    $voted[$e['s']] = 1;
            $attendees = array_filter($d['students'] ?? [], fn($st) => empty($st['left']));
            if ($attendees !== [] && !array_diff_key($attendees, $voted))
                close_vote($d, time(), 'all');
            return ['save' => true, 'body' => ['ok'=>true, 'val'=>$val]];
        }));
    }

    if ($action === 'list') {
        /* Alle Sessions, die mit diesem Passwort UND dieser E-Mail-Adresse angelegt wurden */
        $pw = (string)($in['pw'] ?? '');
        $mail = mb_strtolower(trim((string)($in['email'] ?? '')));
        $out = [];
        /* Passwort passt, aber E-Mail passt nicht (alt: leer oder andere Adresse)
           -> als „unmatched" melden: der Dozent kann sie explizit zuordnen */
        $unmatched = 0;
        foreach (glob($DATA_DIR . '/sess_*.json') ?: [] as $f) {
            $sidOf = substr(basename($f, '.json'), 5); // aus Dateinamen, Inhalt ist chiffriert
            if (!sid_ok($sidOf)) continue;
            $d = load_sess($sidOf);
            if (!is_array($d) || empty($d['id'])) continue;
            if (!owner_ok($d, $sidOf, $pw)) continue;
            /* Login-Gesamtsperre: E-Mail muss (case-insensitive) exakt passen.
               Alles andere zaehlt als unmatched und bleibt dem claim-Vorgang. */
            $sessMail = mb_strtolower(trim((string)($d['email'] ?? '')));
            if ($sessMail !== $mail) { $unmatched++; continue; }
            $evs = $d['events'] ?? [];
            $last = 0;
            foreach ($evs as $e) { $last = max($last, (int)$e['t']); }
            $limit = (int)($d['started_at'] ?? 0) + (int)($d['planned_min'] ?? 0) * 60 + 21600;
            $out[] = [
                'id' => $d['id'],
                'running' => !empty($d['started_at']) && empty($d['stopped_at'])
                    && time() <= $limit,
                /* Kategorie für die Übersicht: live (läuft), planned (Starttermin
                   gesetzt, noch nicht gestartet), template (Vorlage ohne
                   festen Termin), archived (beendet) */
                'status' => !empty($d['stopped_at']) ? 'archived'
                    : (!empty($d['started_at']) ? (time() <= $limit ? 'live' : 'archived')
                    : (empty($d['sched_start']) ? 'template' : 'planned')),
                'title' => (string)($d['title'] ?? ''),
                'lecturer' => (string)($d['lecturer'] ?? ''),
                'email' => (string)($d['email'] ?? ''),
                'institute' => (string)($d['institute'] ?? ''),
                'planned_min' => (int)($d['planned_min'] ?? 0),
                'started_at' => $d['started_at'] ?? null,
                'stopped_at' => $d['stopped_at'] ?? null,
                'sched_start' => $d['sched_start'] ?? null,
                'sched_end' => $d['sched_end'] ?? null,
                'students' => count(array_filter($d['students'] ?? [], fn($st) => empty($st['left']))),
                'events' => count($evs),
                'last_activity' => $last ?: null,
            ];
        }
        usort($out, function ($a, $b) { return ($b['last_activity'] ?? 0) <=> ($a['last_activity'] ?? 0); });
        echo json_encode(['ok'=>true, 'sessions'=>$out, 'unmatched'=>$unmatched]); exit;
    }

    if ($action === 'claim') {
        /* Explizite Zuordnung: alle Sessions, die zum Passwort passen, deren
           E-Mail aber leer oder eine andere ist, bekommen die Login-E-Mail.
           Nur der Passwort-Inhaber kann das — danach gelten sie als normale
           Sessions dieses Logins. */
        $pw = (string)($in['pw'] ?? '');
        $mail = trim((string)($in['email'] ?? ''));
        if (strlen($pw) < 4 || !filter_var($mail, FILTER_VALIDATE_EMAIL)) {
            http_response_code(400);
            echo json_encode(['ok'=>false,'error'=>emsg('Valide E-Mail-Adresse und Passwort (mind. 4 Zeichen) angeben','Provide a valid email address and password (min. 4 characters)')]); exit;
        }
        $n = 0;
        foreach (glob($DATA_DIR . '/sess_*.json') ?: [] as $f) {
            $sidOf = substr(basename($f, '.json'), 5);
            if (!sid_ok($sidOf)) continue;
            $res = sess_mutate($sidOf, function (array &$d) use ($sidOf, $pw, $mail, &$n) {
                if (!owner_ok($d, $sidOf, $pw)) return ['save' => false];
                /* Bereits exakt diese E-Mail? Dann nichts zu tun. */
                if (mb_strtolower(trim((string)($d['email'] ?? ''))) === mb_strtolower($mail)) return ['save' => false];
                $d['email'] = $mail;
                $n++;
                return ['save' => true];
            });
            if (($res['code'] ?? 0) === 404) continue; // kaputte Dateien ignorieren
        }
        echo json_encode(['ok'=>true, 'claimed'=>$n]); exit;
    }

    if ($action === 'export') {
        /* Zentrale Ablage als Download — nur mit gültigem Dozenten-Passwort */
        $s = (string)($in['s'] ?? '');
        if (!sid_ok($s)) { http_response_code(404); echo json_encode(['ok'=>false,'error'=>'not found']); exit; }
        autostop($s);
        $d = load_sess($s);
        if (!$d || !owner_ok($d, $s, (string)($in['pw'] ?? ''))) {
            http_response_code(404); echo json_encode(['ok'=>false,'error'=>'not found']); exit;
        }
        [$fname, $payload] = export_payload($d, $s);
        header('Content-Disposition: attachment; filename="' . $fname . '"');
        echo $payload; exit;
    }

    if ($action === 'delete') {
        /* Archiv-Datei endgültig löschen — nur mit gültigem Dozenten-Passwort */
        $s = (string)($in['s'] ?? '');
        if (!sid_ok($s) || !is_file(spath($s))) { http_response_code(404); echo json_encode(['ok'=>false,'error'=>'not found']); exit; }
        $d = load_sess($s);
        if (!$d || !owner_ok($d, $s, (string)($in['pw'] ?? ''))) {
            http_response_code(404); echo json_encode(['ok'=>false,'error'=>'not found']); exit;
        }
        @unlink(spath($s));
        @unlink(spath($s) . '.lock'); // Sperr-Datei mit aufräumen
        echo json_encode(['ok'=>true]); exit;
    }

    http_response_code(400); echo json_encode(['ok'=>false,'error'=>'unknown action']); exit;
}

/* ---------------- GET-API ---------------- */
$s = (string)($_GET['s'] ?? '');
if (sid_ok($s)) {
    autostop($s);
    $api = $_GET['api'] ?? '';

    if ($api === 'snapshot') {
        header('Content-Type: application/json; charset=utf-8');
        advance_state($s);
        $d = load_sess($s);
        if (is_array($d)) { unset($d['export_key'], $d['owner']); $d['now'] = time(); } // Interna nie herausrücken
        echo json_encode($d ?? ['ok'=>false]); exit;
    }

    if ($api === 'stream') {
        /* Server-Sent Events: bei Dateiänderung sofort Snapshot pushen */
        if (!is_file(spath($s))) { http_response_code(404); exit(($_GET['lang'] ?? 'de') === 'en' ? 'Session not found.' : 'Session nicht gefunden.'); }
        session_write_close();
        @set_time_limit(0);
        ignore_user_abort(false);
        header('Content-Type: text/event-stream; charset=utf-8');
        header('Cache-Control: no-cache');
        header('X-Accel-Buffering: no');
        header('Connection: keep-alive');
        $lastRev = -1; $start = time();
        while (!connection_aborted() && (time() - $start) < 7500) { // max ~2h, EventSource reconnectet
            autostop($s);
            advance_state($s);
            $d = load_sess($s);
            if ($d === null) { echo "event: gone\ndata: {}\n\n"; @ob_flush(); @flush(); break; }
            unset($d['export_key'], $d['owner']); // Interna nie über den Stream verraten
            $d['now'] = time();
            if (($d['rev'] ?? 0) !== $lastRev) {
                $lastRev = $d['rev'] ?? 0;
                echo "data: " . json_encode($d, JSON_UNESCAPED_UNICODE) . "\n\n";
            } else {
                echo ": ping\n\n"; // Heartbeat gegen Proxy-Timeouts
            }
            @ob_flush(); @flush();
            sleep(1);
        }
        exit;
    }

    /* ?s=ID ohne api -> Studenten-Ansicht */
    student_view($s);
    exit;
}

/* ---------------- Standard: Dozenten-Ansicht ---------------- */
lecturer_view();
exit;

/* ============================================================ */
/* Zentrale Ablage: beschreibt das Diagramm + alle Texte, mit Zeitlabels
   passend zum Diagramm, in vollständiger Server-Zeit. Liefert [Dateiname, JSON]. */
function export_payload(array $d, string $s): array {
    $tz = date_default_timezone_get();
    $fs = function ($ts) use ($tz) { return date('Y-m-d H:i:s', (int)$ts) . ' (' . $tz . ')'; };
    $t0 = (int)($d['started_at'] ?? 0);
    $planned = (int)($d['planned_min']);
    $evs = $d['events'] ?? [];
    usort($evs, function ($a, $b) { return $a['t'] - $b['t']; });

    /* Timeline exakt wie im Diagramm (Replay aller Events inkl. undef) */
    $joinSt = join_state_of($d);
    $joined = 0; $in = 0; $undef = 0; $timeline = [];
    if ($t0) $timeline[] = ['min' => 0.0, 'datetime' => $fs($t0), 'joined' => 0, 'in' => 0, 'out' => 0, 'undef' => 0];
    foreach ($evs as $e) {
        $rel = $t0 ? max(0.0, ((int)$e['t'] - $t0) / 60) : 0.0;
        if ($e['kind'] === 'join') { $joined++; if ($joinSt === 'in') { $in++; } else { $undef++; } }
        elseif ($e['kind'] === 'in') { $in++; if ($undef > 0) $undef--; }
        elseif ($e['kind'] === 'out') { $in--; if ($undef > 0) $undef--; }
        elseif ($e['kind'] === 'undef') { if ($in > 0) $in--; $undef++; }
        elseif ($e['kind'] === 'leave') { $joined--; if ($in > 0) $in--; elseif ($undef > 0) $undef--; }
        $timeline[] = [
            'min' => round($rel, 2),
            'datetime' => $fs((int)$e['t']),
            'kind' => $e['kind'],
            'joined' => max(0, $joined),
            'in' => max(0, $in),
            'out' => max(0, $joined - $in - $undef),
            'undef' => max(0, $undef),
        ];
    }
    $now = time();
    $end = $t0 ? max($now, $t0 + $planned * 60) : $now;
    if ($t0) {
        $timeline[] = [
            'min' => round(($end - $t0) / 60, 2),
            'datetime' => $fs($end),
            'joined' => max(0, $joined), 'in' => max(0, $in),
            'out' => max(0, $joined - $in - $undef), 'undef' => max(0, $undef),
        ];
    }

    /* Alle gesendeten Texte mit Emoji, Status und Zeitlabels */
    $stateMap = ['in'=>'IN','out'=>'OUT','undef'=>'UNDEF','join'=>'JOIN','leave'=>'LEAVE','eval'=>'EVAL',
                 'warn'=>'DECIDE-REQ','decided'=>'DECIDED','voteopen'=>'VOTE-OPEN','voteclose'=>'VOTE-CLOSE'];
    $messages = [];
    $votesByRound = [];
    foreach ($evs as $e) {
        $rel = $t0 ? max(0.0, ((int)$e['t'] - $t0) / 60) : 0.0;
        if ($e['kind'] === 'vote') {
            $r = (int)($e['round'] ?? 0);
            $votesByRound[$r][] = (int)($e['val'] ?? 0);
            $messages[] = [
                'time_offset_min' => round($rel, 2),
                'datetime' => $fs((int)$e['t']),
                'state' => 'VOTE',
                'vote_round' => $r,
                'vote_value' => (int)($e['val'] ?? 0),
                'emoji' => $e['emoji'],
                'message' => $e['msg'],
            ];
            continue;
        }
        $m = ['time_offset_min' => round($rel, 2),
              'datetime' => $fs((int)$e['t']),
              'state' => $stateMap[$e['kind']] ?? strtoupper((string)$e['kind']),
              'slide' => (int)($e['slide'] ?? 0) ?: null,
              'emoji' => $e['emoji'],
              'message' => $e['msg']];
        if ($e['kind'] === 'warn') $m['by'] = $e['by'] ?? 'lecturer';
        if ($e['kind'] === 'decided') { $m['counts_before'] = $e['cnt'] ?? null; $m['counts_after'] = $e['cnt2'] ?? null; }
        if ($e['kind'] === 'eval') {
            $m['question'] = $e['qq'] ?? '';
            $m['answer'] = $e['a'] ?? '';
            $m['comment'] = $e['msg'] ?? '';
        }
        if ($e['kind'] === 'voteclose') {
            $m['votes'] = $e['votes'] ?? null;
            $m['close_mode'] = $e['mode'] ?? 'auto';
            $m['package'] = (int)($e['pack'] ?? 0);
            $m['voters'] = (int)($e['voters'] ?? 0);
            $m['present'] = (int)($e['present'] ?? 0);
        }
        $messages[] = $m;
    }
    /* Abstimmungsergebnisse je Runde (1–9, 0 = Enthaltung) */
    $voteResults = [];
    foreach ($votesByRound as $r => $vals) {
        $cnt = array_count_values($vals);
        ksort($cnt);
        $totalR = count($vals);
        $pctR = [];
        foreach ($cnt as $v => $c) $pctR[$v] = $totalR ? round($c / $totalR * 100) : 0;
        $voteResults['round_' . $r] = [
            'total_votes' => $totalR,
            'by_value' => $cnt,
            'by_value_percent' => $pctR,
        ];
    }

    $stamp = $t0 ?: (int)($evs[0]['t'] ?? $now);
    $fname = date('Ymd-His', $stamp) . '-' . $planned . 'min-' . $s . '.json';

    /* Übersicht: echte und geplante Zeiten im gewünschten Format */
    $hm = function ($sec) { $sec = max(0, (int)$sec); return sprintf('%02d:%02d', intdiv($sec, 3600), intdiv($sec % 3600, 60)); };
    $stopTs = (int)($d['stopped_at'] ?? 0);
    $durIst = ($t0 && $stopTs) ? $stopTs - $t0 : ($t0 ? max(0, $now - $t0) : 0);
    $startGeplant = !empty($d['sched_start']) ? $fs((int)$d['sched_start']) : null;
    $stopGeplant  = !empty($d['sched_end']) ? $fs((int)$d['sched_end'])
                   : (!empty($d['expected_end']) ? $fs((int)$d['expected_end']) : null);
    $summary = [
        'Dauer ' . $hm($durIst) . ', geplant ' . $hm($planned * 60),
        'Start ' . ($t0 ? $fs($t0) : '—') . ($startGeplant ? ' (geplant ' . $startGeplant . ')' : ''),
        'Stop ' . ($stopTs ? $fs($stopTs) : '—')
            . ($stopGeplant ? ' (geplant ' . $stopGeplant . ')' : '')
            . (isset($d['stop_by']) ? ' [' . $d['stop_by'] . ']' : ''),
    ];

    $payload = json_encode([
        'session_id' => $s,
        'title' => (string)($d['title'] ?? ''),
        'lecturer' => (string)($d['lecturer'] ?? ''),
        'email' => (string)($d['email'] ?? ''),
        'institute' => (string)($d['institute'] ?? ''),
        'timezone' => $tz,
        'lecture_start' => $t0 ? $fs($t0) : null,
        'lecture_started' => (bool)$t0,
        'planned_duration_min' => $planned,
        'summary' => $summary,
        'stop_by' => $d['stop_by'] ?? null,
        'scheduled_start' => !empty($d['sched_start']) ? $fs((int)$d['sched_start']) : null,
        'scheduled_end' => !empty($d['sched_end']) ? $fs((int)$d['sched_end']) : null,
        'expected_end' => !empty($d['expected_end']) ? $fs((int)$d['expected_end']) : null,
        'exported_at' => $fs($now),
        'students_currently_joined' => count(array_filter($d['students'] ?? [], fn($st) => empty($st['left']))),
        'final_state' => ['in' => max(0, $in), 'out' => max(0, $joined - $in - $undef), 'undef' => max(0, $undef)],
        'start_in_default' => !empty($d['start_in']),
        'ask_mode' => ask_mode_of($d),
        'warn_min' => (int)($d['warn_min'] ?? 0),
        'vote_packages' => $d['vote_packs'] ?? [],
        'evaluation_questions' => $d['eval_qs'] ?? [],
        'votes' => $voteResults,
        'diagram' => $timeline,
        'messages' => $messages,
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
    return [$fname, $payload];
}

function lecturer_view(): void {
?>
<!DOCTYPE html>
<html lang="de">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Lecture Tool ATX — Dozent</title>
<script src="https://cdn.jsdelivr.net/npm/qrcodejs@1.0.0/qrcode.min.js"></script>
<style>
:root{--bg:#101418;--card:#1a2027;--fg:#e8edf2;--muted:#8b98a5;--green:#2ecc71;--red:#e74c3c;--orange:#f39c12}
*{box-sizing:border-box}
body{margin:0;font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;background:var(--bg);color:var(--fg)}
header{padding:18px 24px 6px;position:relative}
h1{font-size:1.25rem;margin:0 0 2px}
header p{margin:0;color:var(--muted);font-size:.85rem}
main{padding:10px 24px 24px;display:flex;flex-direction:column;gap:16px}
.card{background:var(--card);border-radius:12px;padding:20px}
.card h3{margin:0 0 10px;font-size:1rem}
label{font-size:.9rem;color:var(--muted)}
input[type=range]{width:100%;accent-color:var(--green)}
input[type=password],input[type=text],input[type=datetime-local]{width:100%;margin-top:8px;padding:10px 12px;border-radius:10px;
  border:1px solid #2a323c;background:#101418;color:var(--fg);font:inherit}
.hindent{margin-left:16px;color:var(--muted);font-size:.85rem}
#sessinfo{margin-bottom:14px;font-weight:700;font-size:1.05rem}
#sessinfo .sub{font-weight:400;color:var(--muted);font-size:.9rem;margin-top:2px}
.check-row{display:flex;gap:8px;align-items:center;margin-top:8px;font-size:.85rem;color:var(--muted)}
.slider-row{display:flex;align-items:center;gap:14px;margin-top:10px}
.slider-val{font-weight:700;font-size:1.3rem;min-width:90px;text-align:right}
button{font:inherit;font-weight:600;border:none;border-radius:10px;padding:12px 22px;cursor:pointer;background:#2c3540;color:var(--fg)}
button:hover{filter:brightness(1.2)}
button.primary{background:var(--green);color:#08130b}
button.danger{background:#4a2422;color:#ffb3ad}
.btn-row{display:flex;gap:10px;flex-wrap:wrap;margin-top:16px}
.hidden{display:none}
#qrwrap{display:flex;gap:28px;align-items:center;flex-wrap:wrap}
#qrbox{background:#fff;padding:14px;border-radius:12px;width:fit-content}
#joinurl{word-break:break-all;color:var(--muted);font-size:.85rem;max-width:420px}
canvas#chart{width:100%;height:340px;display:block;touch-action:pan-y;cursor:crosshair}
.status{font-size:.85rem;color:var(--muted)}
.live-dot{display:inline-block;width:9px;height:9px;border-radius:50%;background:var(--green);margin-right:6px;animation:pulse 1.5s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}
.bigbtn{padding:14px 28px;border:none;border-radius:16px;font-size:1.05rem;font-weight:700;
  color:#fff;cursor:pointer;transition:all .25s}
.bigbtn.inglow{background:#145c33;box-shadow:0 0 26px 6px var(--green);animation:pulse 2.2s infinite}
.bigbtn.outglow{background:#4a1512;box-shadow:0 0 26px 6px var(--red);animation:pulse 2.2s infinite}
.bigbtn.dimmed{opacity:.55;box-shadow:0 0 8px 0 rgba(255,255,255,.15);animation:none;filter:none}
.hint{font-size:.8rem;color:var(--muted)}
.hrow{display:flex;justify-content:space-between;align-items:center;gap:12px;
  padding:10px 0;border-bottom:1px solid #2a323c;flex-wrap:wrap}
.hrow:last-child{border-bottom:none}
.hrow .btns{display:flex;gap:8px}
.hrow button{padding:8px 14px;font-size:.85rem}
#archbar{display:flex;align-items:center;gap:12px;margin-bottom:10px}
#archbar.hidden{display:none}
#archbar button{padding:8px 14px;font-size:.85rem}
.chat{margin-top:14px;height:240px;overflow-y:auto;display:flex;flex-direction:column;gap:8px;border-top:1px solid #2a323c;padding-top:12px}
#bigtime{display:flex;justify-content:center;align-items:baseline;gap:20px;margin-top:26px;font-weight:800;font-size:3.2rem;letter-spacing:1px;font-variant-numeric:tabular-nums}
#bigtime .yellow{color:#f1c40f}
#bigtime .red{color:#e74c3c}
#bigtime .gray{color:#8b98a5}
#bigtime .blink{animation:pulse 1s infinite}
#bigtime .bsep{color:var(--muted);font-weight:400;font-size:2rem}
#bigtime.arch{font-size:1.05rem;font-weight:600;flex-direction:column;gap:3px;align-items:center}
#archtime{display:flex;flex-direction:column;gap:3px;align-items:center;margin-bottom:10px;
  font-size:1.05rem;font-weight:600}
#archtime.hidden{display:none}
#archtime .pl{color:var(--muted);font-weight:400}
.chat h3{margin:0 0 2px;font-size:.9rem;color:var(--muted)}
.bubble{max-width:75%;padding:8px 12px;border-radius:12px;font-size:.88rem;line-height:1.35}
.bubble.out{align-self:flex-start;background:#3a201e;border-left:4px solid var(--red);border-radius:4px 12px 12px 12px}
.bubble.in{align-self:flex-end;background:#183626;border-right:4px solid var(--green);border-radius:12px 4px 12px 12px}
.bubble .meta{font-size:.72rem;color:var(--muted);margin-bottom:2px}
.sys{align-self:center;color:var(--muted);font-size:.78rem}
.sysbox{align-self:center;max-width:100%;background:#142433;border:1px solid #3498db;border-left:4px solid #3498db;
  border-radius:10px;color:#bcd6ea;font-size:.82rem;padding:8px 12px;margin:2px 0}
/* Mini-Balkendiagramm im Abstimmungs-Ergebniskasten: kompakt, aufsteigend aufgedeckt */
.vchart{display:flex;flex-direction:column;gap:3px;margin-top:6px;min-width:180px}
.vrow{display:flex;align-items:center;gap:6px;font-size:.78rem}
.vlab{width:4.6em;text-align:right;color:#e8edf2;flex:none;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.vtrack{flex:1;height:10px;background:rgba(255,255,255,.05);border-radius:3px;overflow:hidden}
.vbar{display:block;height:100%;border-radius:3px;width:0;
  animation:vgrow .7s ease-out forwards;animation-delay:var(--d,0s)}
@keyframes vgrow{to{width:var(--w,0%)}}
.vcnt{color:#8b98a5;flex:none;min-width:4.5em;white-space:nowrap}
.vsum{opacity:0;margin-top:6px;font-size:.78rem;color:#bcd6ea;
  animation:vfade .5s ease-out forwards;animation-delay:var(--d,0s)}
.vtitle{font-weight:700;color:#e8edf2;margin-bottom:4px;font-size:.85rem}
.vturn{font-size:.78rem;color:#8fb4d4;margin-bottom:2px}
@keyframes vfade{to{opacity:1}}
.bubble.undef{align-self:center;background:#1e2630;border:1px solid #8b98a5;border-radius:10px}
.bubble.eval{align-self:flex-end;background:#33290f;border-right:4px solid #f1c40f;border-radius:12px 4px 12px 12px}
.chatmark{border-top:2px solid #f1c40f;opacity:.85;align-self:stretch;margin:2px 0}
#langsw{position:absolute;top:14px;right:18px;display:flex;gap:6px}
#langsw button{padding:5px 10px;font-size:.8rem;border-radius:8px;background:#2c3540;font-weight:600}
#langsw button.on{background:var(--green);color:#08130b}
body.lang-de .en{display:none}
body.lang-en .de{display:none}
details.legal summary{cursor:pointer;color:var(--muted);font-weight:600;font-size:.9rem}
details.legal .legal-body{font-size:.82rem;color:var(--muted);line-height:1.55;margin-top:10px}
details.legal h4{margin:12px 0 4px;color:var(--fg);font-size:.85rem}
details.legal p,details.legal li{margin:4px 0}
.hrow .btns{flex:none}
.cathead{margin:16px 0 6px;font-weight:700;font-size:.95rem;color:var(--fg)}
#loginbox{border:1px solid #2a323c;border-radius:12px;background:#0c1014;padding:12px 14px;margin-bottom:18px}
@keyframes loginshake{0%,100%{transform:translateX(0)}25%{transform:translateX(-7px)}75%{transform:translateX(7px)}}
#loginbox.loginerr{border-color:var(--red)!important;box-shadow:0 0 0 2px rgba(231,76,60,.35);animation:loginshake .3s 2}
#loginbox h3{margin:0 0 10px}
#loginbox label{display:block;margin-top:8px}
details.legal ul{margin:4px 0;padding-left:20px}
details.legal a{color:var(--green)}
</style>
</head>
<body>
<header>
  <div id="langsw">
    <button id="btnLangDe" onclick="setLang('de')">🇩🇪 DE</button>
    <button id="btnLangEn" onclick="setLang('en')">🇬🇧 EN</button>
  </div>
  <h1>🎓 Lecture Tool ATX</h1>
  <p><span class="de">Dozenten-Ansicht</span><span class="en">Lecturer view</span> · <span class="de">ATX steht für „Attention Tracker“</span><span class="en">ATX stands for “Attention Tracker”</span></p>
</header>
<main>

  <div class="card" id="setup">
    <div id="loginbox">
      <h3>🔐 <span class="de">Login</span><span class="en">Login</span></h3>
      <label for="mail">✉ <span class="de">E-Mail</span><span class="en">Email</span></label>
      <input type="email" id="mail" data-ph="mail" autocomplete="email">
      <label for="pw">🔑 <span class="de">Passwort</span><span class="en">Password</span></label>
      <input type="password" id="pw" data-ph="pw" autocomplete="current-password">
      <div class="check-row"><input type="checkbox" id="pwsave" checked> <span class="de">Passwort auf diesem Gerät speichern</span><span class="en">Save password on this device</span></div>
      <button id="btnMySessions" style="width:100%;margin-top:12px" onclick="goMySessions()">📚 <span class="de">Lade Sessions</span><span class="en">Load sessions</span></button>
      <div id="histfound" class="hidden" style="margin-top:10px;font-size:.92rem"></div>
    </div>
    <label for="title" style="display:block;margin-top:18px"><span class="de">Titel der Vorlesung (optional)</span><span class="en">Lecture title (optional)</span></label>
    <input type="text" id="title" data-ph="title">
    <label for="lect" style="display:block;margin-top:14px"><span class="de">Dozent (optional)</span><span class="en">Lecturer (optional)</span></label>
    <input type="text" id="lect" data-ph="lect">
    <label for="inst" style="display:block;margin-top:14px"><span class="de">Institut (optional)</span><span class="en">Institute (optional)</span></label>
    <input type="text" id="inst" data-ph="inst">
    <label for="dur" style="display:block;margin-top:18px"><span class="de">Geplante Vorlesungsdauer</span><span class="en">Planned lecture duration</span></label>
    <div class="slider-row">
      <input type="range" id="dur" min="5" max="720" step="5" value="90" oninput="document.getElementById('durval').textContent=this.value+' min'">
      <span class="slider-val" id="durval">90 min</span>
    </div>
    <label for="vpacks" style="display:block;margin-top:12px"><span class="de">🗳 Abstimmungspakete (optional)</span><span class="en">🗳 Vote packages (optional)</span></label>
    <textarea id="vpacks" rows="4" style="width:100%;margin-top:8px;background:#101418;color:var(--fg);border:1px solid #2a323c;border-radius:10px;padding:10px;font:inherit;resize:vertical"></textarea>
    <div class="hint"><span class="de">Format: 1. Zeile = Überschrift, darunter je Zeile eine Option. Leere Zeile = nächstes Paket. Die Pakete erscheinen später im Dropdown vor dem Abstimmen-Knopf.</span><span class="en">Format: line 1 = heading, then one option per line. Empty line = next package. Packages appear later in the dropdown next to the vote button.</span></div>
    <label for="evalq" style="display:block;margin-top:12px"><span class="de">📝 Bewertung (optional)</span><span class="en">📝 Evaluation (optional)</span></label>
    <textarea id="evalq" rows="4" style="width:100%;margin-top:8px;background:#101418;color:var(--fg);border:1px solid #2a323c;border-radius:10px;padding:10px;font:inherit;resize:vertical"></textarea>
    <div class="hint"><span class="de">Format: Frage in eine Zeile, darunter die Antwortmöglichkeiten mit | getrennt. Mit |c am Ende gibt es zusätzlich ein Textfeld. Nur „|c“ ohne Optionen = reine Kommentarfrage (z. B. „Was schlägst du sonst noch vor?“). Die Studenten sehen die Fragen erst nach dem Stopp, eine nach der anderen.</span><span class="en">Format: question on one line, answer options below separated by |. Ending with |c adds a free-text field. Just „|c“ without options = comment-only question. Students only see the questions after the lecture stops, one at a time.</span></div>
    <div style="margin-top:14px;padding:12px 14px;border:1px solid #2a323c;border-radius:12px;background:#0c1014">
      <div style="font-weight:700;margin-bottom:4px">🧭 <span class="de">Status-Abfrage der Studenten</span><span class="en">Student status polling</span></div>
      <div style="display:flex;align-items:center;gap:8px;margin-top:8px;flex-wrap:wrap">
        <input type="radio" name="askmode" value="start" id="am-start">
        <label for="am-start" style="cursor:pointer">
          <span class="de">Studenten starten im Zustand „IN“ — Änderungen melden sie jederzeit selbst</span>
          <span class="en">Students start in the “IN” state — they report changes themselves anytime</span>
        </label>
      </div>
      <div style="display:flex;align-items:center;gap:8px;margin-top:8px;flex-wrap:wrap">
        <input type="radio" name="askmode" value="auto" id="am-auto">
        <label for="am-auto" style="cursor:pointer">
          <span class="de">Automatische Neuentscheidung alle X Minuten — erste Abfrage direkt zum Start</span>
          <span class="en">Automatic re-decision every X minutes — first poll right at the start</span>
        </label>
        <select id="warnmin" onchange="document.getElementById('am-auto').checked = true" style="padding:4px 8px;border-radius:8px;border:1px solid #2a323c;background:#101418;color:var(--fg);font:inherit;font-size:.85rem">
          <option value="5">5</option><option value="10">10</option><option value="15">15</option><option value="30">30</option>
          <option value="45">45</option><option value="60">60</option><option value="90">90</option><option value="120">120</option>
        </select>
        <span class="de">Minuten</span><span class="en">minutes</span>
      </div>
      <div style="display:flex;align-items:flex-start;gap:8px;margin-top:8px">
        <input type="radio" name="askmode" value="ondemand" id="am-ondemand" checked>
        <label for="am-ondemand" style="cursor:pointer">
          <span class="de">On demand: Alle Studenten bleiben „undef“, bis du in der Vorlesung über „Prüfen“ gezielt abfragst — beliebig oft wiederholbar</span>
          <span class="en">On demand: all students stay “undefined” until you ask via “Check” during the lecture — repeatable anytime</span>
        </label>
      </div>
      <div class="hint" style="margin-top:6px"><span class="de">On demand (Standard): „Prüfen“ öffnet eine 60-Sekunden-Abfrage an alle Studenten; Unentschlossene werden danach „undef“. IN/OUT ist in diesem Modus nur während einer Abfrage möglich. Automatisch: Zu Beginn der Vorlesung entscheiden sich alle Studenten einmal direkt, danach alle X Minuten erneut.</span><span class="en">On demand (default): “Check” opens a 60-second poll for all students; anyone undecided becomes “undefined” afterwards. In this mode IN/OUT is only possible during a poll. Automatic: at the start of the lecture all students decide once right away, then again every X minutes.</span></div>
    </div>
    <div style="display:flex;gap:12px;margin-top:14px;flex-wrap:wrap">
      <div style="flex:1;min-width:180px">
        <label for="schedStart" style="display:block"><span class="de">Geplanter Beginn (optional)</span><span class="en">Planned start (optional)</span></label>
        <input type="datetime-local" id="schedStart">
      </div>
      <div style="flex:1;min-width:180px">
        <label for="schedEnd" style="display:block"><span class="de">Geplantes Ende (optional)</span><span class="en">Planned end (optional)</span></label>
        <input type="datetime-local" id="schedEnd">
      </div>
    </div>
    <div class="btn-row">
      <button class="primary" id="btnstart" onclick="startSession()"><span class="de">Erstellen</span><span class="en">Create</span></button>
    </div>
  </div>

  <dialog id="shareDlg" style="border:none;border-radius:14px;padding:22px;max-width:440px;width:92%;background:#0c1014;color:#e8edf2">
    <h3 style="margin:0 0 12px">✅ <span class="de">Vorlesung erstellt</span><span class="en">Lecture created</span></h3>
    <div id="dlginfo" style="font-size:.92rem;line-height:1.6"></div>
    <div style="text-align:center;margin:14px 0 6px"><div id="dlgqr" style="display:inline-block;background:#fff;padding:10px;border-radius:10px"></div></div>
