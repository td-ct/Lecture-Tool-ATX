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
        $ask_mode    = (string)($in['ask_mode'] ?? 'start');         // Standard: Start IN, Selbstmeldung
        if (!in_array($ask_mode, ['start', 'auto', 'ondemand'], true)) $ask_mode = 'start';
        if ($ask_mode === 'ondemand') { $start_in = false; $warn_min = 0; } // alle undef bis zur ersten „Prüfen“-Abfrage
        elseif ($ask_mode === 'auto') {   $start_in = false; }              // undef bis zur Abfrage direkt zum Start
        else {                           $start_in = true; $warn_min = 0; } // 'start': Start IN, Selbstmeldung, keine Runden
        /* Pro-Einstellungen: Dozenten-/Studentenansicht + Feature-Schalter */
        $lecview = (string)($in['lecview'] ?? 'pie');
        if (!in_array($lecview, ['pie', 'figures', 'chart'], true)) $lecview = 'pie';
        $stuview = (($in['stuview'] ?? 'round') === 'classic') ? 'classic' : 'round';
        $allow_msg   = !empty($in['allow_msg']);
        $allow_votes = !empty($in['allow_votes']);
        $allow_eval  = !empty($in['allow_eval']);
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
            'lecview' => $lecview,
            'stuview' => $stuview,
            'allow_msg' => $allow_msg,
            'allow_votes' => $allow_votes,
            'allow_eval' => $allow_eval,
            'decide_seq' => 0,
            'decide_until' => 0,
            'vote_no' => 0,
            'vote_until' => 0,
            'vote_pack' => 0,
            'vote_packs' => $allow_votes ? parse_vote_packs((string)($in['vote_packs'] ?? '')) : [],
            'eval_qs' => $allow_eval ? parse_eval_qs((string)($in['evalq'] ?? '')) : [],
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
            if (empty($d['allow_msg'])) $msg = ''; // Nachrichten für diese Veranstaltung deaktiviert
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
        $s = (string)($in['s'] ?? '');        if (!sid_ok($s)) { http_response_code(400); echo json_encode(['ok'=>false,'error'=>'bad session']); exit; }
        $pw = (string)($in['pw'] ?? '');
        $pack = max(0, (int)($in['pack'] ?? 0));
        reply(sess_mutate($s, function (array &$d) use ($s, $pw, $pack) {
            if (!owner_ok($d, $s, $pw)) return ['code' => 403, 'body' => ['ok'=>false,'error'=>emsg('falsches Passwort','wrong password')]];
            if (empty($d['allow_votes'])) return ['code' => 403, 'body' => ['ok'=>false,'error'=>emsg('Umfragen sind für diese Veranstaltung deaktiviert','Polls are disabled for this event')]];
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
            if (empty($d['allow_eval'])) return ['code' => 403, 'body' => ['ok'=>false,'error'=>emsg('Die Abschlussbewertung ist für diese Veranstaltung deaktiviert','The final evaluation is disabled for this event')]];
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
                'lecview' => (string)($d['lecview'] ?? 'chart'),
                'stuview' => (string)($d['stuview'] ?? 'classic'),
                'ask_mode' => ask_mode_of($d),
                'allow_msg' => !empty($d['allow_msg']),
                'allow_votes' => !empty($d['allow_votes']),
                'allow_eval' => !empty($d['allow_eval']),
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
.prosub{margin:10px 0;padding:10px 12px;border:1px solid #2a323c;border-radius:10px;background:#10141a}
.prosub summary{cursor:pointer;font-weight:600}
#figwrap{margin-top:8px}
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
    <details id="probox" style="margin-top:14px;border:1px solid #2a323c;border-radius:12px;background:#0c1014;padding:12px 14px">
      <summary style="font-weight:700;cursor:pointer">⚙️ <span class="de">Pro-Einstellungen</span><span class="en">Pro settings</span></summary>

      <details class="prosub">
        <summary>📊 <span class="de">Dozenten-Ansicht</span><span class="en">Lecturer view</span></summary>
        <div style="display:flex;align-items:flex-start;gap:8px;margin-top:8px">
          <input type="radio" name="lecview" value="pie" id="lv-pie" checked>
          <label for="lv-pie" style="cursor:pointer">
            <span class="de">🥧 Einfaches Tortendiagramm mit roten, gelben und grünen Anteilen — die Anzahl je Teil steht als Beschriftung dabei (Standard)</span>
            <span class="en">🥧 Simple pie chart with red, yellow and green shares — each labelled with its count (default)</span>
          </label>
        </div>
        <div style="display:flex;align-items:flex-start;gap:8px;margin-top:8px">
          <input type="radio" name="lecview" value="figures" id="lv-fig">
          <label for="lv-fig" style="cursor:pointer">
            <span class="de">🧍 Strichmännchen-Gruppe: grüne sind dabei, unentschlossene sind gelb — wer auf OUT wechselt, verlässt als rotes Strichmännchen die Menge</span>
            <span class="en">🧍 Stick-figure group: green ones are in, undecided are yellow — switching to OUT makes a red figure leave the crowd</span>
          </label>
        </div>
        <div style="display:flex;align-items:flex-start;gap:8px;margin-top:8px">
          <input type="radio" name="lecview" value="chart" id="lv-chart">
          <label for="lv-chart" style="cursor:pointer">
            <span class="de">📈 Zeitverlaufs-Diagramm (bisherige Ansicht) mit transparent farbigen Flächen unter den Kurven</span>
            <span class="en">📈 Timeline chart (previous view) with translucent coloured areas under the curves</span>
          </label>
        </div>
      </details>

      <details class="prosub">
        <summary>📱 <span class="de">Studenten-Ansicht</span><span class="en">Student view</span></summary>
        <div style="display:flex;align-items:flex-start;gap:8px;margin-top:8px">
          <input type="radio" name="stuview" value="round" id="sv-round" checked>
          <label for="sv-round" style="cursor:pointer">
            <span class="de">⭕ Ein runder Knopf mit den Zuständen IN und OUT — ein Tipp genügt (Standard)</span>
            <span class="en">⭕ One round button with the IN and OUT states — a single tap (default)</span>
          </label>
        </div>
        <div style="display:flex;align-items:flex-start;gap:8px;margin-top:8px">
          <input type="radio" name="stuview" value="classic" id="sv-classic">
          <label for="sv-classic" style="cursor:pointer">
            <span class="de">✅😴 Bisherige Ansicht: zwei Knöpfe plus Auswahl von Emoji, Folie und optionaler Nachricht</span>
            <span class="en">✅😴 Previous view: two buttons plus emoji, slide and optional message selection</span>
          </label>
        </div>
      </details>

      <details class="prosub">
        <summary>🧭 <span class="de">Status-Abfrage der Studenten</span><span class="en">Student status polling</span></summary>
      <div style="display:flex;align-items:center;gap:8px;margin-top:8px;flex-wrap:wrap">
        <input type="radio" name="askmode" value="start" id="am-start" checked>
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
        <input type="radio" name="askmode" value="ondemand" id="am-ondemand">
        <label for="am-ondemand" style="cursor:pointer">
          <span class="de">On demand: Alle Studenten bleiben „undef“, bis du in der Vorlesung über „Prüfen“ gezielt abfragst — beliebig oft wiederholbar</span>
          <span class="en">On demand: all students stay “undefined” until you ask via “Check” during the lecture — repeatable anytime</span>
        </label>
      </div>
      <div class="hint" style="margin-top:6px"><span class="de">Standard: „IN“ beim Beitritt — Änderungen melden die Studenten jederzeit selbst. Automatisch: alle entscheiden sich zum Start und dann alle X Minuten erneut. On demand: „Prüfen“ öffnet eine 60-Sekunden-Abfrage an alle Studenten; IN/OUT ist in diesem Modus nur während einer Abfrage möglich.</span><span class="en">Default: “IN” on joining — students report changes themselves anytime. Automatic: everyone decides at the start and again every X minutes. On demand: “Check” opens a 60-second poll for all students; in this mode IN/OUT is only possible during a poll.</span></div>
      </details>

      <details class="prosub">
        <summary>💬 <span class="de">Studenten-Nachrichten</span><span class="en">Student messages</span></summary>
        <div class="check-row" style="margin-top:8px">
          <input type="checkbox" id="msgon">
          <label for="msgon" style="cursor:pointer">
            <span class="de">Studenten können beim Statuswechsel eine kurze Nachricht schreiben</span>
            <span class="en">Students can write a short message when changing their status</span>
          </label>
        </div>
        <div class="hint"><span class="de">Standardmäßig aus — die Statuswechsel laufen dann ohne Nachrichteneingabe.</span><span class="en">Off by default — status changes then happen without a message field.</span></div>
      </details>

      <details class="prosub">
        <summary>🗳 <span class="de">Umfragen</span><span class="en">Polls</span></summary>
        <div class="check-row" style="margin-top:8px">
          <input type="checkbox" id="voteson">
          <label for="voteson" style="cursor:pointer">
            <span class="de">Umfragen während der Vorlesung ermöglichen</span>
            <span class="en">Enable polls during the lecture</span>
          </label>
        </div>
        <div id="vpackwrap" class="hidden">
          <label for="vpacks" style="display:block;margin-top:8px"><span class="de">Abstimmungspakete (optional)</span><span class="en">Vote packages (optional)</span></label>
          <textarea id="vpacks" rows="4" style="width:100%;margin-top:8px;background:#101418;color:var(--fg);border:1px solid #2a323c;border-radius:10px;padding:10px;font:inherit;resize:vertical"></textarea>
          <div class="hint"><span class="de">Format: 1. Zeile = Überschrift, darunter je Zeile eine Option. Leere Zeile = nächstes Paket. Die Pakete erscheinen später im Dropdown vor dem Abstimmen-Knopf.</span><span class="en">Format: line 1 = heading, then one option per line. Empty line = next package. Packages appear later in the dropdown next to the vote button.</span></div>
        </div>
        <div class="hint"><span class="de">Standardmäßig aus — der Abstimmen-Knopf bleibt dann ausgeblendet.</span><span class="en">Off by default — the vote button stays hidden then.</span></div>
      </details>

      <details class="prosub">
        <summary>📝 <span class="de">Abschluss-Feedback</span><span class="en">Final feedback</span></summary>
        <div class="check-row" style="margin-top:8px">
          <input type="checkbox" id="evalon">
          <label for="evalon" style="cursor:pointer">
            <span class="de">Nach dem Abschluss Feedback der Studenten einholen</span>
            <span class="en">Collect student feedback after the event ends</span>
          </label>
        </div>
        <div id="evalqwrap" class="hidden">
          <label for="evalq" style="display:block;margin-top:8px"><span class="de">Bewertungsfragen</span><span class="en">Evaluation questions</span></label>
          <textarea id="evalq" rows="4" style="width:100%;margin-top:8px;background:#101418;color:var(--fg);border:1px solid #2a323c;border-radius:10px;padding:10px;font:inherit;resize:vertical"></textarea>
          <div class="hint"><span class="de">Format: Frage in eine Zeile, darunter die Antwortmöglichkeiten mit | getrennt. Mit |c am Ende gibt es zusätzlich ein Textfeld. Nur „|c“ ohne Optionen = reine Kommentarfrage (z. B. „Was schlägst du sonst noch vor?“). Die Studenten sehen die Fragen erst nach dem Stopp, eine nach der anderen — bis 24 Stunden lang.</span><span class="en">Format: question on one line, answer options below separated by |. Ending with |c adds a free-text field. Just „|c“ without options = comment-only question. Students only see the questions after the lecture stops, one at a time — for up to 24 hours.</span></div>
        </div>
        <div class="hint"><span class="de">Standardmäßig aus — die Studenten sehen nach dem Ende dann keine Bewertung.</span><span class="en">Off by default — students then see no evaluation after the end.</span></div>
      </details>
    </details>
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
    <div id="dlgurl" style="word-break:break-all;font-size:.85rem;color:#8b98a5;margin:6px 0 6px"></div>
    <div id="dlghint" style="font-size:.8rem;color:#8b98a5;margin:0 0 16px"></div>
    <div class="btn-row">
      <button class="primary" id="dlgShare">📤 <span class="de">Teilen</span><span class="en">Share</span></button>
      <button id="dlgQrDl">⬇ <span class="de">QR-Code herunterladen</span><span class="en">Download QR code</span></button>
      <button id="dlgCopy">🔗 <span class="de">Link kopieren</span><span class="en">Copy link</span></button>
    </div>
    <div class="btn-row" style="margin-top:10px">
      <button class="primary" id="dlgGo" style="flex:1">➡ <span class="de">Zur Dozenten-Ansicht</span><span class="en">To lecturer view</span></button>
      <button id="dlgHome" style="flex:1">🏠 <span class="de">Zurück zur Übersicht</span><span class="en">Back to overview</span></button>
    </div>
  </dialog>

  <div class="card" id="history">
    <h3>📚 <span class="de">Meine Sessions</span><span class="en">My sessions</span></h3>
    <div id="histlist"></div>
  </div>

  <div class="card hidden" id="run">
    <div id="sessinfo"></div>
    <div id="qrwrap">
      <div id="qrbox"><div id="qr"></div></div>
      <div>
        <div style="font-weight:700;margin-bottom:6px"><span class="de">Beitritts-Link (Session</span><span class="en">Join link (session</span> <span id="sid"></span>)</div>
        <div id="joinurl"></div>
        <div class="btn-row" style="gap:14px">
          <button class="bigbtn inglow" id="btnLecStart" onclick="startLecture()">▶ <span class="de">Timer starten</span><span class="en">Start timer</span></button>
        </div>
        <div class="btn-row" style="gap:14px;margin-top:12px;align-items:center;flex-wrap:wrap">
          <button id="btnTest" onclick="testAsk()">🔍 <span class="de">Prüfen</span><span class="en">Check</span></button>
          <select id="vpacksel" class="hidden" style="padding:10px 12px;border-radius:10px;border:1px solid #2a323c;background:#101418;color:var(--fg);font:inherit"></select>
          <button id="btnVote" onclick="startVote()">🗳 <span class="de">Abstimmen</span><span class="en">Vote</span></button>
        </div>
        <div class="btn-row hidden" id="voteCtl" style="gap:14px;margin-top:12px;align-items:center">
          <span style="font-weight:700;color:#f1c40f;font-variant-numeric:tabular-nums">⏱ <span id="voteRem">60</span>&nbsp;s</span>
          <button onclick="voteExtend()">＋1 min</button>
          <button onclick="voteStopNow()">⏹ <span class="de">Beenden</span><span class="en">End now</span></button>
        </div>
        <div class="status" style="margin-top:12px"><span class="live-dot"></span><span id="stat"><span class="de">Live — warte auf Studenten …</span><span class="en">Live — waiting for students …</span></span></div>
      </div>
    </div>
  </div>

  <div class="card hidden" id="chartcard">
    <div id="archbar" class="hidden">
      <button onclick="showHome()"><span class="de">◀ Zurück zur Übersicht</span><span class="en">◀ Back to overview</span></button>
      <span class="status" id="archinfo"></span>
      <div style="display:flex;flex-direction:column;gap:6px;margin-left:auto">
        <button class="danger hidden" id="btnDel" onclick="deleteSession()"><span class="de">🗑 Löschen</span><span class="en">🗑 Delete</span></button>
        <button id="btnReuse" class="hidden" onclick="reuseSettings()">🔄 <span class="de">Einstellungen übernehmen</span><span class="en">Reuse settings</span></button>
      </div>
    </div>
    <div id="otherlive" class="hidden" style="margin:10px 0 0;padding:8px 12px;border:1px solid #5a4a1a;border-radius:10px;background:#1c1a10;font-size:.9rem"></div>
    <div id="archtime" class="hidden"></div>
    <canvas id="chart"></canvas>
    <div id="figwrap" class="hidden"></div>
    <div id="bigtime"></div>
    <div class="chat" id="chat"><h3>💬 Messages</h3></div>
    <div class="btn-row">
      <button onclick="exportJson()"><span class="de">📥 Datenexport (JSON)</span><span class="en">📥 Export data (JSON)</span></button>
      <button class="danger" id="btnLecStop" onclick="stopLecture()">🏁 <span class="de">Veranstaltung beenden</span><span class="en">End event</span></button>
      <button class="danger" id="btnRestart" onclick="restart()"><span class="de">🔄 Neue Vorlesung</span><span class="en">🔄 New lecture</span></button>
    </div>
  </div>

  <div class="btn-row" id="logoutrow" style="justify-content:center">
    <button class="danger" onclick="logout()"><span class="de">Verlassen &amp; abmelden</span><span class="en">Leave &amp; logout</span></button>
  </div>

  <div class="card" id="legal">
    <details class="legal">
      <summary> Impressum / <span class="en">Legal notice</span></summary>
      <div class="legal-body">
        <div class="de">
          <h4>Angaben gemäß § 5 DDG</h4>
          <p>Timo Damm<br>Butten 2<br>24107 Kiel<br>Deutschland</p>
          <p>E-Mail: <a href="mailto:info@pixcaelium.de">info@pixcaelium.de</a></p>
          <p>Verantwortlich für den Inhalt dieser Seite: Timo Damm, Anschrift wie oben.</p>
        </div>
        <div class="en">
          <h4>Information pursuant to § 5 DDG (German Digital Services Act)</h4>
          <p>Timo Damm<br>Butten 2<br>24107 Kiel<br>Germany</p>
          <p>Email: <a href="mailto:info@pixcaelium.de">info@pixcaelium.de</a></p>
          <p>Responsible for the content of this page: Timo Damm, address as above.</p>
        </div>
      </div>
    </details>
    <details class="legal">
      <summary> Datenschutzerklärung / <span class="en">Privacy policy</span></summary>
      <div class="legal-body">
        <div class="de">
          <p>Diese Anwendung verarbeitet personenbezogene Daten sparsam und im Einklang mit der DSGVO. Im Einzelnen:</p>
          <ul>
            <li>Die App verwendet <b>keine Cookies</b> und kein Tracking, keine Analyse- und keine Werbedienste.</li>
            <li><b>Anonymität:</b> Beim Öffnen der Studenten-Ansicht erzeugt dein Browser ein rein zufälliges Token (lokal im localStorage deines Geräts). Es enthält keine personenbezogenen Angaben und ist nicht mit dir identifizierbar. Name, E-Mail oder Matrikelnummer werden nicht erhoben; IP-Adressen werden nicht protokolliert.</li>
            <li><b>Studenten-Eingaben</b> (IN/OUT, Emoji, Nachricht, Abstimmung, Bewertung, Foliennummer) werden ohne Personenbezug dauerhaft und verschlüsselt (AES-256-GCM) auf dem Server der Veranstaltung gespeichert. Die Abschlussbewertung kann bis 24 Stunden nach Veranstaltungsende nachgereicht werden, auch nach dem Verlassen der Veranstaltung. <b>Freitext-Hinweis:</b> Bitte in Nachrichten und Kommentaren keine personenbezogenen Angaben (z. B. Namen oder Kontaktdaten) eingeben — sie werden gespeichert, bis der Dozent die Veranstaltung löscht.</li>
            <li><b>Dozenten-Zugang:</b> Das Passwort wird ausschließlich als Hash in der verschlüsselten Session-Datei gespeichert; wählst du „auf diesem Gerät speichern", liegt es zusätzlich in deinem lokalen Browser-Speicher. Name, E-Mail und Institut werden verschlüsselt in jeder Session hinterlegt; E-Mail und Passwort-Hash bilden deinen Login und ordnen dir deine Sessions in der Übersicht zu. Auch geplante Veranstaltungen und Vorlagen bleiben so lange gespeichert, bis du sie löschst.</li>
            <li><b>Speicherdauer:</b> Die Daten einer Vorlesung bleiben so lange gespeichert, bis der Dozent sie über den Löschen-Knopf entfernt. Ein Export als JSON-Datei ist jederzeit möglich.</li>
            <li><b>Datenübertragung:</b> Alle Dienste laufen auf dem Server dieser Veranstaltung. Beim Laden der Dozenten-Ansicht wird lediglich die QR-Code-Bibliothek von einem öffentlichen CDN (jsdelivr) geladen; dabei wird deine IP-Adresse an das CDN übermittelt.</li>
            <li><b>Keine Weitergabe:</b> Es findet keine Übermittlung an sonstige Dritte statt.</li>
            <li><b>Deine Rechte:</b> Nach DSGVO bestehen die Rechte auf Auskunft (Art. 15), Berichtigung (Art. 16), Löschung (Art. 17), Einschränkung der Verarbeitung (Art. 18) und Datenübertragbarkeit (Art. 20). Da keine personenbezogenen Daten erhoben und Rückmeldungen nicht zuordnungsbar gespeichert werden, können diese Rechte nur auf selbst angegebene Freitexte Anwendung finden — diese kannst du per E-Mail geltend machen. Zudem besteht das Recht auf Beschwerde bei einer Datenschutz-Aufsichtsbehörde (Art. 77).</li>
          </ul>
          <p>Fragen, Auskunft oder Löschung: <a href="mailto:info@pixcaelium.de">info@pixcaelium.de</a></p>
        </div>
        <div class="en">
          <p>This application processes personal data sparingly and in accordance with the GDPR. In detail:</p>
          <ul>
            <li>The app uses <b>no cookies</b> and no tracking, analytics or advertising services.</li>
            <li><b>Anonymity:</b> When you open the student view, your browser generates a purely random token (locally in your device's localStorage). It contains no personal data and cannot identify you. Name, email or matriculation number are not collected; IP addresses are not logged.</li>
            <li><b>Student input</b> (IN/OUT, emoji, message, vote, evaluation, slide number) is stored permanently and encrypted (AES-256-GCM) on the event's server without any personal reference. The final evaluation can be submitted up to 24 hours after the event has ended, even after leaving it. <b>Free-text note:</b> Please do not enter personal details (e.g. names or contact data) in messages and comments — they are stored until the lecturer deletes the event.</li>
            <li><b>Lecturer account:</b> The password is stored only as a hash inside the encrypted session file; if you choose “save on this device”, it is additionally kept in your browser's local storage. Name, email and institute are stored encrypted in each session; email and password hash form your login and assign your sessions to you in the overview. Planned events and templates are also kept until you delete them.</li>
            <li><b>Retention:</b> A lecture's data is kept until the lecturer deletes it via the delete button. An export as a JSON file is possible at any time.</li>
            <li><b>Data transfer:</b> All services run on the event's own server. When loading the lecturer view, only the QR code library is fetched from a public CDN (jsdelivr); your IP address is transmitted to that CDN.</li>
            <li><b>No sharing:</b> Data is not transmitted to any other third party.</li>
            <li><b>Your rights:</b> Under the GDPR you have the rights of access (Art. 15), rectification (Art. 16), erasure (Art. 17), restriction of processing (Art. 18) and data portability (Art. 20). Since no personal data is collected and feedback is stored without attribution, these rights can only apply to free-text entries you provide yourself — you may assert them by email. You also have the right to lodge a complaint with a supervisory data protection authority (Art. 77).</li>
          </ul>
          <p>Questions, information or deletion: <a href="mailto:info@pixcaelium.de">info@pixcaelium.de</a></p>
        </div>
      </div>
    </details>
    <details class="legal">
      <summary> <span class="de">Danksagung</span><span class="en">Credits</span></summary>
      <div class="legal-body">
        <div class="de">
          <p>Die Grundidee zum Attention Tracker stammt von <b>Franziska Lohrengel</b> und <b>Jan-Bernd Hövener</b> — herzlichen Dank für den entscheidenden Funken, aus dem das Lecture Tool ATX entstanden ist.</p>
        </div>
        <div class="en">
          <p>The original idea for the attention tracker is credited to <b>Franziska Lohrengel</b> and <b>Jan-Bernd Hövener</b> — many thanks for the decisive spark from which Lecture Tool ATX grew.</p>
        </div>
      </div>
    </details>
  </div>

</main>
<script>
const LSKEY = 'attention_lecturer_sid';
const LSPW  = 'attention_lecturer_pw';
let session = null, es = null, curId = null;
let archive = false, archEnd = 0, archiveId = null;

/* ---------------- Sprachumschaltung DE/EN ---------------- */
let LANG = localStorage.getItem('att_lang') || 'de';
const I18N = {
  de: {
    pwShort: 'Bitte zuerst ein Dozenten-Passwort (mind. 4 Zeichen) eingeben.',
    mailShort: 'Bitte eine E-Mail-Adresse angeben — nur damit werden dir deine archivierten Vorlesungen angezeigt.',
    srvErr: 'Server-Fehler beim Erzeugen der Session — bitte Server-Log prüfen.',
    err: 'Fehler: ',
    histPw: '▲ Zur Anmeldung: E-Mail und Passwort oben eingeben',
    histNone: 'Keine Sessions zu dieser E-Mail und diesem Passwort.',
    copied: 'Link kopiert.',
    shareNa: 'Teilen wird von diesem Browser nicht unterstützt — der Link wurde stattdessen kopiert.',
    shareText: function(ti){ return 'Vorlesung mit dem Lecture Tool ATX' + (ti ? ': ' + ti : ''); },
    sessId: 'Session-ID',
    catLive: '🔴 Live — läuft jetzt',
    catPlanned: '📅 Geplant — mit Starttermin',
    catTemplate: '📋 Vorlagen — ohne festen Termin',
    catArch: '📁 Abgeschlossen',
    otherLive: '🔴 Weitere Live-Vorlesungen',
    foundLec: function(n){ return n === 1 ? 'Vorlesung gefunden' : n + ' Vorlesungen gefunden'; },
    foundGo: 'Zur Liste springen',
    legacyHint: function(n){ return 'Zusätzlich ' + (n === 1 ? 'passt eine Vorlesung' : 'passen ' + n + ' Vorlesungen') + ' zu deinem Passwort, aber nicht zu dieser E-Mail-Adresse:'; },
    legacyBtn: '🔄 Diese Vorlesung(en) diesem Login zuordnen',
    claimAsk: function(n){ return (n === 1 ? 'Eine Vorlesung' : n + ' Vorlesungen') + ' mit diesem Passwort wird/werden auf deine aktuelle E-Mail-Adresse umgeschrieben und erscheinen danach dauerhaft in deiner Liste. Fortfahren?'; },
    claimDone: function(n){ return (n === 1 ? 'Eine Vorlesung wurde' : n + ' Vorlesungen wurden') + ' deinem Login zugeordnet.'; },
    claimNone: 'Keine Vorlesungen ohne E-Mail-Zuordnung gefunden.',
    dlgHint: 'Der Link und der QR-Code gelten ab jetzt und unbegrenzt. Studenten können schon vor Vorlesungsbeginn beitreten — sie warten dann auf den Start.',
    notStarted: 'nicht gestartet',
    planned: 'geplant: ',
    students: ' Student(en)',
    events: ' Events',
    view: '📊 Ansehen',
    geplant2: '⏱ geplant: ',
    beginn: 'Beginn: ',
    ende: 'Ende: ',
    notFound: 'Session nicht gefunden.',
    archTag: ' · Archiv ',
    msgs: '💬 Messages',
    msgsArch: '💬 Messages (Archiv)',
    delPw: 'Löschen nur mit Passwort aus der Dozenten-Ansicht möglich.',
    delFail: 'Löschen fehlgeschlagen — Passwort falsch?',
    liveInfo: 'Live — Session ',
    qrErr: 'QR-Bibliothek nicht geladen — Studenten können den Link unten manuell eintippen.',
    stopConfirm: 'Veranstaltung beenden? Die Aufzeichnung wird geschlossen und die Aufzeichnungsdaten (JSON) direkt als Download angeboten.',
    expPw: 'Export nur mit Passwort aus der Dozenten-Ansicht möglich.',
    expFail: 'Export fehlgeschlagen — Passwort falsch?',
    logoutConfirm: 'Damit meldest du dich vom Lecture Tool ATX ab und beendest deine Dozenten-Session. Beim nächsten Mal ist wieder eine Passworteingabe nötig. Fortfahren?',
    restartConfirm: 'Zur Übersicht wechseln und eine neue Vorlesung vorbereiten? Die aktuelle Vorlesung bleibt dabei unangetastet — sie läuft ggf. weiter und steht in der Übersicht unter „Live“ oder im Archiv.',
    chatStu: '🔍 Verlauf eines Studenten — klicken zum Zurücksetzen',
    chatRange: '🕒 Zeitraum-Auswahl — klick ins Diagramm zum Zurücksetzen',
    joinMsg: '👤 Student beigetreten [',
    leaveMsg: '🚪 Student hat verlassen [',
    minEnd: ' min]',
    chartWait: '⏸ Warte auf Start',
    chartDone: '🏁 Beendet',
    archStart: 'Start ',
    archStop: 'Stop ',
    archDur: 'Dauer ',
    archPlanned: ' (geplant ',
    archParen: ')',
    archNone: '—',
    noTitle: 'Ohne Titel',
    legSched: 'geplante Zeiten',
    legNow: 'aktuelle Zeit',
    legStart: 'Start/Stopp (real)',
    legUndef: 'undef',
    sysWarnLec: '🔔 Neuentscheidung angefordert (manuell) · vorher: ',
    sysWarnAuto: '🔔 Neuentscheidung gefordert (automatisch) · vorher: ',
    sysDecided: '✅ Neuentscheidung abgeschlossen · jetzt: ',
    sysVoteOpen: '🗳 Abstimmung eröffnet (60 s)',
    sysVoteRes: '🗳 Abstimmungsergebnis: ',
    sysVoteAll: '✅ Alle haben abgestimmt —',
    sysTurnout: function(v,p){ return '🗳 '+v+' von '+p+' Studenten haben abgestimmt'; },
    slideLbl: 'Folie',
    sysVoteStop: '⏹ Abstimmung beendet —',
    evalLbl: 'Bewertung',
    abstain: 'Enthaltung',
    noVotes: 'keine Stimmen',
    cntFmt: function(i,o,u){ return i+' IN · '+o+' OUT · '+u+' undef'; },
    legNow: 'aktuelle Zeit',
    legStart: 'Start/Stopp (real)',
    statNot: '⏸ noch nicht gestartet — ',
    statLive: function(j,i,o,u){ return 'Live — '+j+' Student(en), davon '+i+' IN, '+o+' OUT, '+u+' undef'; },
    delConfirmFull: function(id){ return 'Diese Vorlesung (Session ' + id + ') wirklich endgültig löschen?\n\nDie zugehörige Datei wird unwiderruflich entfernt und kann nicht wiederhergestellt werden.'; }
  },
  en: {
    pwShort: 'Please enter a lecturer password first (min. 4 characters).',
    mailShort: 'Please provide an email address — your archived lectures are only shown with it.',
    srvErr: 'Server error while creating the session — please check the server log.',
    err: 'Error: ',
    histPw: '▲ To the login: enter email and password above',
    histNone: 'No sessions for this email and password.',
    copied: 'Link copied.',
    shareNa: 'Sharing is not supported by this browser — the link was copied instead.',
    shareText: function(ti){ return 'Lecture with the Lecture Tool ATX' + (ti ? ': ' + ti : ''); },
    sessId: 'Session ID',
    catLive: '🔴 Live — running now',
    catPlanned: '📅 Planned — with scheduled date',
    catTemplate: '📋 Templates — no fixed date',
    catArch: '📁 Finished',
    otherLive: '🔴 Other live lectures',
    foundLec: function(n){ return n === 1 ? 'lecture found' : n + ' lectures found'; },
    foundGo: 'Jump to list',
    legacyHint: function(n){ return 'In addition, ' + (n === 1 ? 'one lecture matches' : n + ' lectures match') + ' your password but not this email address:'; },
    legacyBtn: '🔄 Assign these lectures to this login',
    claimAsk: function(n){ return (n === 1 ? 'One lecture' : n + ' lectures') + ' with this password will be reassigned to your current email address and appear in your list from now on. Continue?'; },
    claimDone: function(n){ return (n === 1 ? 'One lecture was' : n + ' lectures were') + ' assigned to your login.'; },
    claimNone: 'No lectures without email assignment found.',
    dlgHint: 'The link and QR code are valid from now on, indefinitely. Students can join before the lecture starts — they will wait for the start.',
    notStarted: 'not started',
    planned: 'planned: ',
    students: ' student(s)',
    events: ' events',
    view: '📊 View',
    geplant2: '⏱ planned: ',
    beginn: 'Start: ',
    ende: 'End: ',
    notFound: 'Session not found.',
    archTag: ' · Archive ',
    msgs: '💬 Messages',
    msgsArch: '💬 Messages (Archive)',
    delPw: 'Deleting requires the lecturer password.',
    delFail: 'Delete failed — wrong password?',
    liveInfo: 'Live — session ',
    qrErr: 'QR library not loaded — students can type the link below manually.',
    stopConfirm: 'End the event? The recording is closed and the recorded data (JSON) is offered as a download right away.',
    expPw: 'Export requires the lecturer password.',
    expFail: 'Export failed — wrong password?',
    logoutConfirm: 'This signs you out of the Lecture Tool ATX and ends your lecturer session. Next time you will need to enter the password again. Continue?',
    restartConfirm: 'Switch to the overview and prepare a new lecture? The current lecture is left untouched — it may keep running and appears under “Live” or in the archive.',
    chatStu: '🔍 One student\u2019s history — click to reset',
    chatRange: '🕒 Time range — click the chart to reset',
    joinMsg: '👤 Student joined [',
    leaveMsg: '🚪 Student left [',
    minEnd: ' min]',
    chartWait: '⏸ Waiting for start',
    chartDone: '🏁 Finished',
    archStart: 'Start ',
    archStop: 'Stop ',
    archDur: 'Duration ',
    archPlanned: ' (planned ',
    archParen: ')',
    archNone: '—',
    noTitle: 'Untitled',
    legSched: 'scheduled times',
    legUndef: 'undef',
    sysWarnLec: '🔔 Re-decision requested (manual) · before: ',
    sysWarnAuto: '🔔 Re-decision requested (automatic) · before: ',
    sysDecided: '✅ Re-decision completed · now: ',
    sysVoteOpen: '🗳 Vote opened (60 s)',
    sysVoteRes: '🗳 Vote result: ',
    sysVoteAll: '✅ Everyone voted —',
    sysTurnout: function(v,p){ return '🗳 '+v+' of '+p+' students voted'; },
    slideLbl: 'slide',
    sysVoteStop: '⏹ Vote ended —',
    evalLbl: 'Evaluation',
    abstain: 'abstain',
    noVotes: 'no votes',
    cntFmt: function(i,o,u){ return i+' IN · '+o+' OUT · '+u+' undef'; },
    legNow: 'current time',
    legStart: 'start/stop (actual)',
    statNot: '⏸ not started yet — ',
    statLive: function(j,i,o,u){ return 'Live — '+j+' student(s), '+i+' IN, '+o+' OUT, '+u+' undef'; },
    delConfirmFull: function(id){ return 'Really delete this lecture (session ' + id + ') permanently?\n\nThe associated file will be irreversibly removed and cannot be restored.'; }
  }
};
function t(k){ const v = (I18N[LANG] && I18N[LANG][k]) || I18N.de[k]; return (typeof v === 'function') ? v : v; }
const PH = {
  pw:    { de: 'Mind. 4 Zeichen',                          en: 'At least 4 characters' },
  title: { de: 'z. B. Radiologie für Fortgeschrittene',    en: 'e.g. Advanced Radiology' },
  lect:  { de: 'Name des Dozenten',                       en: 'Lecturer name' },
  mail:  { de: 'name@uksh.de',                            en: 'name@example.org' },
  inst:  { de: 'z. B. Institut für Radiologie',           en: 'e.g. Institute of Radiology' }
};
function applyPh(){
  document.querySelectorAll('input[data-ph]').forEach(el => { el.placeholder = PH[el.dataset.ph][LANG]; });
}
function setLang(l){
  LANG = l; localStorage.setItem('att_lang', l);
  document.body.classList.remove('lang-de','lang-en'); document.body.classList.add('lang-'+l);
  document.documentElement.lang = l;
  document.getElementById('btnLangDe').classList.toggle('on', l==='de');
  document.getElementById('btnLangEn').classList.toggle('on', l==='en');
  applyPh();
  if(session) render();
  loadHistory();
}
document.body.classList.add(LANG === 'en' ? 'lang-en' : 'lang-de');
setLang(LANG);

function api(body){
  body = Object.assign({lang: LANG}, body); // Server-Meldungen in der UI-Sprache
  return fetch(location.pathname, {
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify(body)
  }).then(r => r.json());
}
function getPw(){ return document.getElementById('pw').value || localStorage.getItem(LSPW) || ''; }
function getMail(){ return document.getElementById('mail').value.trim(); }

/* Login: erst wenn E-Mail UND Passwort (mind. 4 Zeichen) stehen, Sessions-Liste laden (debounced) */
let pwTimer = null;
function loginChanged(){
  clearTimeout(pwTimer);
  if(getMail() && getPw().length >= 4) pwTimer = setTimeout(loadHistory, 350);
}
document.getElementById('pw').addEventListener('input', loginChanged);
document.getElementById('mail').addEventListener('input', loginChanged);

/* Pro-Bereich: Optionspakete/Bewertungsfragen erst zeigen, wenn aktiviert */
function proToggles(){
  document.getElementById('vpackwrap').classList.toggle('hidden', !document.getElementById('voteson').checked);
  document.getElementById('evalqwrap').classList.toggle('hidden', !document.getElementById('evalon').checked);
}
document.getElementById('voteson').addEventListener('change', proToggles);
document.getElementById('evalon').addEventListener('change', proToggles);
proToggles();

/* Dauer / Beginn / Ende: sind zwei gesetzt, wird die dritte automatisch berechnet.
   Nur Dauer gesetzt ist ebenfalls erlaubt (Beginn & Ende bleiben offen). */
function toTs(v){ return v ? Math.floor(new Date(v).getTime()/1000) : 0; }
function setDT(id, ts){
  const d = new Date(ts*1000), p = n => String(n).padStart(2,'0');
  document.getElementById(id).value =
    d.getFullYear()+'-'+p(d.getMonth()+1)+'-'+p(d.getDate())+'T'+p(d.getHours())+':'+p(d.getMinutes());
}
function setDur(min){
  min = Math.max(5, Math.min(720, Math.round(min/5)*5));
  const el = document.getElementById('dur');
  el.value = min;
  document.getElementById('durval').textContent = min + ' min';
  return min;
}
function syncTimes(changed){
  const durEl = document.getElementById('dur');
  let dur = +durEl.value;
  const sEl = document.getElementById('schedStart'), eEl = document.getElementById('schedEnd');
  const sTs = toTs(sEl.value), eTs = toTs(eEl.value);
  if(changed === 'dur'){
    if(sTs)       setDT('schedEnd', sTs + dur*60);       // Dauer + Beginn -> Ende
    else if(eTs)  setDT('schedStart', eTs - dur*60);     // Dauer + Ende -> Beginn
  } else if(changed === 'start'){
    if(eTs)       setDur(Math.round((eTs - sTs)/60));    // Beginn + Ende -> Dauer
    else          setDT('schedEnd', sTs + dur*60);
  } else if(changed === 'end'){
    if(sTs)       setDur(Math.round((eTs - sTs)/60));
    else          setDT('schedStart', eTs - dur*60);
  }
}
document.getElementById('dur').addEventListener('input', () => syncTimes('dur'));
document.getElementById('schedStart').addEventListener('change', () => syncTimes('start'));
document.getElementById('schedEnd').addEventListener('change', () => syncTimes('end'));

async function startSession(){
  const pw = getPw();
  if(!pw || pw.length < 4) return alert(t('pwShort'));
  const email = document.getElementById('mail').value.trim();
  if(!email) return alert(t('mailShort'));
  if(document.getElementById('pwsave').checked) localStorage.setItem(LSPW, pw);
  const planned = +document.getElementById('dur').value;
  const title = document.getElementById('title').value.trim();
  const lecturer = document.getElementById('lect').value.trim();
  const institute = document.getElementById('inst').value.trim();
  const sched_start = toTs(document.getElementById('schedStart').value);
  const sched_end   = toTs(document.getElementById('schedEnd').value);
  const warn_min    = +document.getElementById('warnmin').value;
  const ask_mode    = (document.querySelector('input[name=askmode]:checked') || {}).value || 'start';
  const lecview     = (document.querySelector('input[name=lecview]:checked') || {}).value || 'pie';
  const stuview     = (document.querySelector('input[name=stuview]:checked') || {}).value || 'round';
  const allow_msg   = document.getElementById('msgon').checked;
  const allow_votes = document.getElementById('voteson').checked;
  const allow_eval  = document.getElementById('evalon').checked;
  const start_in    = ask_mode === 'start'; /* Server normalisiert je Modus, hier nur mitsenden */
  const vote_packs  = document.getElementById('vpacks').value;
  const evalq       = document.getElementById('evalq').value;
  let r;
  try{
    r = await api({action:'create', planned_min: planned, title, lecturer, email, institute, sched_start, sched_end, start_in, warn_min, ask_mode, lecview, stuview, allow_msg, allow_votes, allow_eval, vote_packs, evalq, pw});
  }catch(e){
    return alert(t('srvErr'));
  }
  if(!r.ok) return alert(t('err') + (r.error||'?'));
  localStorage.setItem(LSKEY, r.id);
  /* Zwischendialog: alle Infos + Link + QR — teilen/herunterladen, dann weiter */
  const schedTxt = (el) => document.getElementById(el).value;
  showShareDlg(r.id, {
    title, lecturer, institute, email,
    planned_min: planned,
    sched_start: schedTxt('schedStart'),
    sched_end:   schedTxt('schedEnd'),
    warn_min, ask_mode
  });
}

/* ---------- Zwischendialog nach dem Erstellen: Infos, Link & QR teilen ---------- */
let dlgPending = null;
function dlgUrl(){ return location.origin + location.pathname + '?s=' + (dlgPending ? dlgPending.id : ''); }
function fmtDT(v){
  if(!v) return '';
  const d = new Date(v), p = n => String(n).padStart(2,'0');
  return d.toLocaleDateString() + ' ' + p(d.getHours()) + ':' + p(d.getMinutes());
}
function showShareDlg(id, meta){
  dlgPending = {id, meta};
  const rows = [];
  if(meta.title)       rows.push('📌 <b>' + escapeHtml(meta.title) + '</b>');
  if(meta.lecturer)    rows.push('👤 ' + escapeHtml(meta.lecturer));
  if(meta.institute)   rows.push('🏛 ' + escapeHtml(meta.institute));
  rows.push('⏱ ' + t('planned') + fmt(meta.planned_min*60));
  if(meta.sched_start) rows.push('🟢 ' + t('beginn') + fmtDT(meta.sched_start));
  if(meta.sched_end)   rows.push('🏁 ' + t('ende') + fmtDT(meta.sched_end));
  rows.push('🆔 ' + t('sessId') + ' <code>' + id + '</code>');
  document.getElementById('dlginfo').innerHTML = rows.join('<br>');
  document.getElementById('dlgurl').textContent = dlgUrl();
  document.getElementById('dlghint').textContent = t('dlgHint');
  const q = document.getElementById('dlgqr'); q.innerHTML = '';
  try{
    new QRCode(q, {text: dlgUrl(), width: 200, height: 200, correctLevel: QRCode.CorrectLevel.M});
  }catch(e){
    q.innerHTML = '<div style="color:#c00;font-size:.8rem;width:200px">'+t('qrErr')+'</div>';
  }
  document.getElementById('shareDlg').showModal();
}
async function copyDlgLink(){
  const url = dlgUrl();
  try{ await navigator.clipboard.writeText(url); }
  catch(e){
    const ta = document.createElement('textarea'); ta.value = url;
    document.body.appendChild(ta); ta.select();
    try{ document.execCommand('copy'); }catch(e2){}
    document.body.removeChild(ta);
  }
}
document.getElementById('dlgCopy').onclick = async () => { await copyDlgLink(); alert(t('copied')); };
document.getElementById('dlgQrDl').onclick = () => {
  const cv = document.querySelector('#dlgqr canvas'), im = document.querySelector('#dlgqr img');
  const src = cv ? cv.toDataURL('image/png') : (im ? im.src : null);
  if(!src) return alert(t('qrErr'));
  const a = document.createElement('a');
  a.href = src; a.download = 'lecture-tool-atx-qr.png';
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
};
document.getElementById('dlgShare').onclick = async () => {
  const url = dlgUrl(), ti = (dlgPending && dlgPending.meta.title) || '';
  const shareData = {title: ti || 'Lecture Tool ATX', text: t('shareText')(ti), url};
  if(navigator.share){
    try{ await navigator.share(shareData); return; }
    catch(e){ if(e.name === 'AbortError') return; }
  }
  await copyDlgLink();
  alert(t('shareNa'));
};
document.getElementById('dlgHome').onclick = () => {
  /* Die Session ist mit „Erstellen“ bereits serverseitig gespeichert —
     zurück zur Übersicht heißt nicht, dass etwas verloren geht. */
  document.getElementById('shareDlg').close();
  dlgPending = null;
  loadHistory();
  document.getElementById('history').scrollIntoView({behavior:'smooth'});
};
document.getElementById('dlgGo').onclick = () => {
  document.getElementById('shareDlg').close();
  const p = dlgPending; dlgPending = null;
  if(!p) return;
  openSession(p.id, {
    title: p.meta.title, lecturer: p.meta.lecturer,
    institute: p.meta.institute, email: p.meta.email,
    planned_min: p.meta.planned_min
  });
  loadHistory();
};

/* ---------- Historie: alle Sessions zu diesem Passwort ---------- */
/* Knopf „Lade Sessions": E-Mail + Passwort aktiv einloggen. Bei Erfolg (oder
   auffindbaren umzuzordnenden Vorlesungen) zur Liste springen, bei Misserfolg
   die Login-Box rot markieren und kurz wackeln lassen. */
function loginErr(){
  const lb = document.getElementById('loginbox');
  lb.classList.remove('loginerr');
  void lb.offsetWidth; /* Animation neu starten */
  lb.classList.add('loginerr');
  setTimeout(() => lb.classList.remove('loginerr'), 2000);
}
async function goMySessions(){
  const pw = getPw(), email = getMail();
  if(!email || !pw || pw.length < 4){ loginErr(); alert(t('histPw')); return; }
  const r = await loadHistory();
  if(r && r.ok && (((r.sessions)||[]).length > 0 || (r.unmatched||0) > 0)){
    document.getElementById('history').scrollIntoView({behavior:'smooth'});
  } else {
    loginErr();
  }
}

/* Fund-Zeile im Login: wie viele Vorlesungen passen, mit Sprung zur Liste;
   zusätzlich Hinweis auf ältere Vorlesungen ohne E-Mail-Zuordnung */
function showFound(n, legacy){
  const f = document.getElementById('histfound');
  let html = '✅ <b>' + n + '</b> ' + t('foundLec')(n) +
    ' — <button onclick="document.getElementById(\'history\').scrollIntoView({behavior:\'smooth\'})">📚 ' + t('foundGo') + '</button>';
  if(legacy > 0) html += '<div style="margin-top:6px;color:var(--muted)">' + t('legacyHint')(legacy) +
    ' <button onclick="claimLegacy()">' + t('legacyBtn') + '</button></div>';
  f.innerHTML = html;
  f.classList.remove('hidden');
}
function hideFound(){ document.getElementById('histfound').classList.add('hidden'); }

/* Ältere Vorlesungen (passendes Passwort, keine E-Mail) diesem Login zuordnen */
let legacyCount = 0; /* vom letzten list-Aufruf, für die Rückfrage */
async function claimLegacy(){
  const pw = getPw(), email = getMail();
  if(!pw || !email) return;
  if(!confirm(t('claimAsk')(legacyCount))) return;
  let r;
  try{ r = await api({action:'claim', pw, email}); }
  catch(e){ return alert(t('srvErr')); }
  if(!r.ok) return alert(t('err') + (r.error||'?'));
  alert((r.claimed || 0) > 0 ? t('claimDone')(r.claimed) : t('claimNone'));
  loadHistory();
}

async function loadHistory(){
  const pw = getPw(), email = getMail();
  const box = document.getElementById('histlist');
  if(!email || !pw || pw.length < 4){
    /* Nicht eingeloggt: Hinweis funktioniert als Rück-Link zur Anmeldung oben */
    box.innerHTML = '<div class="hint"><button onclick="document.getElementById(\'mail\').scrollIntoView({behavior:\'smooth\',block:\'center\')">'+t('histPw')+'</button></div>';
    hideFound(); return null;
  }
  const r = await api({action:'list', pw, email});
  if(!r.ok){ box.innerHTML = '<div class="hint">'+escapeHtml(r.error||t('err'))+'</div>'; hideFound(); return r; }
  if(!r.sessions.length){
    legacyCount = r.unmatched || 0;
    box.innerHTML = (r.unmatched > 0)
      ? '<div class="hint">'+t('legacyHint')(r.unmatched)+' <button onclick="claimLegacy()">'+t('legacyBtn')+'</button></div>'
      : '<div class="hint">'+t('histNone')+'</div>';
    if(r.unmatched > 0) showFound(0, r.unmatched); else hideFound();
    return r;
  }
  legacyCount = r.unmatched || 0;
  showFound(r.sessions.length, r.unmatched || 0);
  /* Name & Institut aus der neuesten Vorlesung vorbelegen
     (nur leere Felder, eigene Eingaben bleiben unangetastet; E-Mail ist Login-Feld) */
  const newest = r.sessions[0];
  const lectEl = document.getElementById('lect'), instEl = document.getElementById('inst');
  if(newest.lecturer && !lectEl.value.trim()) lectEl.value = newest.lecturer;
  if(newest.institute && !instEl.value.trim()) instEl.value = newest.institute;
  box.innerHTML = '';
  /* Vier feste Abschnitte: Live immer oben, dann Geplant (nach Starttermin),
     Vorlagen (ohne festen Termin), zuletzt Abgeschlossene */
  const live = [], planned = [], templates = [], arch = [];
  r.sessions.forEach(x => {
    if(x.status === 'live') live.push(x);
    else if(x.status === 'planned') planned.push(x);
    else if(x.status === 'template') templates.push(x);
    else arch.push(x);
  });
  /* Live: zuletzt begonnen oben; Geplant: nächste zuerst; Vorlagen: neueste zuerst */
  live.sort((a,b) => (b.started_at||0) - (a.started_at||0));
  planned.sort((a,b) => (a.sched_start||0) - (b.sched_start||0));
  templates.sort((a,b) => (b.last_activity||0) - (a.last_activity||0));
  arch.sort((a,b) => (b.last_activity||0) - (a.last_activity||0));
  const mkRow = (x, cat) => {
    const row = document.createElement('div');
    row.className = 'hrow';
    const info = document.createElement('div');
    const dt = cat === 'planned'
      ? (x.sched_start ? new Date(x.sched_start*1000).toLocaleString() : t('notStarted'))
      : (x.started_at ? new Date(x.started_at*1000).toLocaleString() : t('notStarted'));
    info.innerHTML = '<b>'+escapeHtml(dt)+'</b>'+
      (cat === 'live' ? ' <span style="color:var(--green);font-weight:700">🔴 Live</span>' : '')+
      (x.title ? '<div class="hindent">📌 '+escapeHtml(x.title)+'</div>' : '') +
      ((x.lecturer || x.email || x.institute || x.planned_min) ? '<div class="hindent">'+
        [x.lecturer ? '👤 '+escapeHtml(x.lecturer) : null,
         x.email ? '✉ '+escapeHtml(x.email) : null,
         x.institute ? '🏛 '+escapeHtml(x.institute) : null,
         t('planned')+fmt(x.planned_min*60),
         x.students+t('students'), x.events+t('events'), 'ID '+escapeHtml(x.id)
        ].filter(Boolean).join(' · ')+'</div>' : '');
    const btns = document.createElement('div');
    btns.className = 'btns';
    btns.innerHTML = '<button onclick="openArchive(\''+x.id+'\')">'+t('view')+'</button>'+
                      '<button onclick="exportJson(\''+x.id+'\')">⬇ JSON</button>';
    row.appendChild(info); row.appendChild(btns);
    return row;
  };
  const addCat = (arr, cat) => {
    if(!arr.length) return;
    const h = document.createElement('div');
    h.className = 'cathead';
    h.textContent = t(cat === 'live' ? 'catLive' : cat === 'planned' ? 'catPlanned' : cat === 'template' ? 'catTemplate' : 'catArch');
    box.appendChild(h);
    arr.forEach(x => box.appendChild(mkRow(x, cat)));
  };
  addCat(live, 'live');
  addCat(planned, 'planned');
  addCat(templates, 'template');
  addCat(arch, 'arch');
}

function fmtDT(ts){ return new Date(ts*1000).toLocaleString(); }
function fillSessInfo(m){
  const title = m.title || t('noTitle');
  const sub = [
    m.lecturer ? '👤 ' + escapeHtml(m.lecturer) : null,
    m.institute ? '🏛 ' + escapeHtml(m.institute) : null,
    m.email ? '✉ ' + escapeHtml(m.email) : null,
    t('geplant2') + fmt((m.planned_min || 0)*60)
  ].filter(Boolean).join(' · ');
  const sched = [];
  if(m.sched_start) sched.push(t('beginn') + fmtDT(m.sched_start));
  if(m.sched_end)   sched.push(t('ende') + fmtDT(m.sched_end));
  document.getElementById('sessinfo').innerHTML =
    '<div>' + escapeHtml(title) + '</div><div class="sub">' + sub + '</div>' +
    (sched.length ? '<div class="sub">🗓 ' + sched.join(' · ') + '</div>' : '');
}

/* ---------- Archiv: Endstand einer alten Session ansehen ---------- */
async function openArchive(id){
  const d = await fetch(location.pathname + '?api=snapshot&s=' + id).then(r=>r.json());
  if(!d || !d.id){ alert(t('notFound')); return; }
  /* Läuft die Aufzeichnung noch oder ist sie (noch) nicht gestartet?
     -> direkt in die Dozenten-Ansicht (QR, Start-Knopf, Live-Stream) */
  if(!d.stopped_at){ openSession(id, d); return; }
  stopLiveBar();
  archive = true; curId = id; archiveId = id; fanfared = true; probeT = null; // Archiv: keine Töne für Altes
  let last = d.started_at || 0;
  (d.events||[]).forEach(e => { last = Math.max(last, e.t); });
  archEnd = Math.max(last,
    d.stopped_at || 0,
    d.started_at ? d.started_at + d.planned_min*60 : 0);
  document.getElementById('setup').classList.add('hidden');
  document.getElementById('history').classList.add('hidden');
  document.getElementById('run').classList.add('hidden');
  document.getElementById('chartcard').classList.remove('hidden');
  document.getElementById('archbar').classList.remove('hidden');
  document.getElementById('archinfo').textContent =
    (d.title ? d.title + (d.lecturer ? ' — ' + d.lecturer : '') : 'Session') +
    (d.institute ? ' · 🏛 ' + d.institute : '') +
    (d.email ? ' · ✉ ' + d.email : '') + t('archTag') + id;
  document.getElementById('chat').innerHTML = '<h3>'+t('msgsArch')+'</h3>';
  document.getElementById('btnRestart').classList.add('hidden'); // Archiv nie löschen
  document.getElementById('btnLecStop').disabled = true;          // Archiv: nichts zu beenden
  document.getElementById('btnDel').classList.remove('hidden'); // Archiv: Löschen erlaubt
  document.getElementById('btnReuse').classList.remove('hidden'); // Einstellungen übernehmbar
  archiveId = id;
  processed = 0; silent = true;
  session = d;
  processEvents(d);
  render();
  document.getElementById('chartcard').scrollIntoView({behavior:'smooth'});
}

function showHome(){
  archive = false; session = null; archiveId = null; probeT = null;
  stopLiveBar();
  if(es){ es.close(); es = null; }
  document.getElementById('chartcard').classList.add('hidden');
  document.getElementById('archbar').classList.add('hidden');
  document.getElementById('btnDel').classList.add('hidden');
  document.getElementById('btnReuse').classList.add('hidden');
  document.getElementById('setup').classList.remove('hidden');
  document.getElementById('history').classList.remove('hidden');
  document.getElementById('logoutrow').classList.remove('hidden');
}

/* Archiv: alle Einstellungen einer alten Vorlesung ins Setup-Formular
   übernehmen (Titel, Dozent, E-Mail, Dauer, Zeiten, Optionen, Bewertung) */
function packsToRaw(packs){
  return (packs || []).map(p => [p.title].concat(p.opts || []).join('\n')).join('\n\n');
}
function evalToRaw(qs){
  return (qs || []).map(q => q.q + '\n' + (q.opts || []).join('|') + (q.cmt ? '|c' : '')).join('\n\n');
}
async function reuseSettings(){
  if(!archiveId) return;
  const d = await fetch(location.pathname + '?api=snapshot&s=' + archiveId).then(r=>r.json());
  if(!d || !d.id){ alert(t('notFound')); return; }
  showHome();
  document.getElementById('title').value = d.title || '';
  document.getElementById('lect').value = d.lecturer || '';
  document.getElementById('mail').value = d.email || '';
  document.getElementById('inst').value = d.institute || '';
  setDur(d.planned_min || 45);
  const sEl = document.getElementById('schedStart'), eEl = document.getElementById('schedEnd');
  if(d.sched_start) setDT('schedStart', d.sched_start); else sEl.value = '';
  if(d.sched_end)   setDT('schedEnd',   d.sched_end);   else eEl.value = '';
  document.getElementById('warnmin').value = String(d.warn_min || 45); /* alte 0-Werte: Standard 45 */
  /* Status-Abfrage-Modus übernehmen; Alt-Sessions ohne Feld: wie bisher ableiten */
  const am = d.ask_mode || (d.warn_min > 0 ? 'auto' : 'start');
  const amEl = document.querySelector('input[name=askmode][value="'+am+'"]');
  if(amEl) amEl.checked = true;
  /* Pro-Einstellungen übernehmen; Alt-Sessions ohne Felder: heutige Standards */
  const lv = document.querySelector('input[name=lecview][value="'+(d.lecview || 'chart')+'"]') || document.getElementById('lv-chart');
  if(lv) lv.checked = true;
  const sv = document.querySelector('input[name=stuview][value="'+(d.stuview || 'classic')+'"]') || document.getElementById('sv-classic');
  if(sv) sv.checked = true;
  document.getElementById('msgon').checked   = !!d.allow_msg;
  document.getElementById('voteson').checked = !!(d.allow_votes || (d.vote_packs||[]).length);
  document.getElementById('evalon').checked  = !!(d.allow_eval || (d.eval_qs||[]).length);
  proToggles();
  document.getElementById('vpacks').value = packsToRaw(d.vote_packs);
  document.getElementById('evalq').value = evalToRaw(d.eval_qs);
  document.getElementById('setup').scrollIntoView({behavior:'smooth'});
}

/* ---------- Archiv-Datei endgültig löschen (nach Warnung) ---------- */
async function deleteSession(idIn){
  const id = idIn || archiveId;
  if(!id) return;
  if(!confirm(t('delConfirmFull')(id))) return;
  const pw = getPw();
  if(!pw){ alert(t('delPw')); return; }
  const r = await api({action:'delete', s:id, pw});
  if(!r || !r.ok){ alert(t('delFail')); return; }
  if(localStorage.getItem(LSKEY) === id) localStorage.removeItem(LSKEY);
  showHome();
  loadHistory();
}

/* ---------- Laufende Vorlesung ---------- */
async function resumeSession(){
  loadHistory();
  const id = localStorage.getItem(LSKEY);
  if(!id) return;
  const d = await fetch(location.pathname + '?api=snapshot&s=' + id).then(r=>r.json());
  /* Nur laufende Vorlesungen automatisch wieder öffnen — geplante bleiben
     in der Übersicht (Kategorie "Geplant"), damit neue vorbereitet werden können */
  if(d && d.id && d.started_at && !d.stopped_at){ openSession(id, d); }
  else { localStorage.removeItem(LSKEY); }
}

function openSession(id, meta){
  archive = false; curId = id;  document.getElementById('setup').classList.add('hidden');
  document.getElementById('history').classList.add('hidden');
  document.getElementById('run').classList.remove('hidden');
  document.getElementById('chartcard').classList.remove('hidden');
  document.getElementById('archbar').classList.remove('hidden');
  document.getElementById('archinfo').textContent = t('liveInfo') + id;
  document.getElementById('btnDel').classList.add('hidden'); // Live: nie löschen
  document.getElementById('logoutrow').classList.add('hidden'); // während der Vorlesung nicht nötig
  document.getElementById('sid').textContent = id;
  document.getElementById('chat').innerHTML = '<h3>'+t('msgs')+'</h3>';
  document.getElementById('btnRestart').classList.remove('hidden');
  archiveId = null;
  fillSessInfo(meta || {});
  processed = 0; silent = true;
  const url = location.origin + location.pathname + '?s=' + id;
  document.getElementById('joinurl').textContent = url;
  const qr = document.getElementById('qr'); qr.innerHTML = '';
  try{
    new QRCode(qr, {text:url, width:220, height:220, correctLevel: QRCode.CorrectLevel.M});
  }catch(e){
    qr.innerHTML = '<div style="color:#c00;font-size:.8rem;width:220px">'+t('qrErr')+'</div>';
  }
  if(meta && meta.started_at){ session = meta; } // Vorab-Stand bis der Stream eintrifft
  fillPackSel();
  /* Schon vorbei am 90%-Punkt oder beendet -> keine Nachhol-Fanfare */
  if(meta && meta.started_at && (meta.stopped_at || Date.now()/1000 - meta.started_at >= 0.9*meta.planned_min*60)) fanfared = true;
  else fanfared = false;
  alarmedStart = false; alarmedEnd = false;
  paintRunControls();
  connectStream(id);
  refreshOtherLive(id);            /* Hinweis auf parallel laufende Vorlesungen */
  startLiveBar();
}

/* --------- Überlappende Live-Sessions: Schnellwechsler in der Ansicht --------- */
let liveBarTimer = null;
function startLiveBar(){
  clearInterval(liveBarTimer);
  liveBarTimer = setInterval(() => refreshOtherLive(curId), 60000);
}
function stopLiveBar(){
  clearInterval(liveBarTimer);
  liveBarTimer = null;
  const b = document.getElementById('otherlive');
  if(b) b.classList.add('hidden');
}
async function refreshOtherLive(excludeId){
  const box = document.getElementById('otherlive');
  if(!box) return;
  const pw = getPw(), email = getMail();
  if(!pw || !email){ box.classList.add('hidden'); return; }
  let r;
  try{ r = await api({action:'list', pw, email}); }
  catch(e){ box.classList.add('hidden'); return; }
  if(!r.ok){ box.classList.add('hidden'); return; }
  const others = (r.sessions || []).filter(x => x.status === 'live' && x.id !== excludeId);
  if(!others.length){ box.classList.add('hidden'); return; }
  box.innerHTML = '<b>'+t('otherLive')+'</b> '+
    others.map(x => '<button onclick="openArchive(\''+x.id+'\')">▶ '+escapeHtml(x.title || x.id)+'</button>').join(' ');
  box.classList.remove('hidden');
}

function connectStream(id){
  if(es) es.close();
  es = new EventSource(location.pathname + '?api=stream&s=' + id + '&lang=' + LANG);
  es.onmessage = e => {
    const d = JSON.parse(e.data);
    session = d;
    fillPackSel(); // Dropdown (falls noch nicht gefüllt)
    processEvents(d);
    paintRunControls();
    render();
  };
  es.addEventListener('gone', () => {
    localStorage.removeItem(LSKEY);
    location.reload();
  });
  es.onerror = () => { /* EventSource reconnectet automatisch */ };
}

function lecState(){
  if(!session) return 'waiting';
  if(session.stopped_at) return 'stopped';
  if(session.started_at) return 'running';
  return 'waiting';
}
function paintRunControls(){
  const st = lecState();
  const bS = document.getElementById('btnLecStart');
  const bX = document.getElementById('btnLecStop');
  bS.className = 'bigbtn inglow' + (st === 'waiting' ? '' : ' dimmed');
  bX.disabled = (st !== 'running'); /* Beenden nur möglich, während sie läuft */
  /* Pro-Gating: Abstimmen-Knopf nur anzeigen, wenn Umfragen aktiviert sind */
  const bV = document.getElementById('btnVote');
  if(bV) bV.classList.toggle('hidden', !(!archive && session && session.allow_votes));
}

async function startLecture(){
  if(lecState() !== 'waiting') return;
  const id = curId || localStorage.getItem(LSKEY);
  if(!id) return;
  const r = await api({action:'start', s:id, pw:getPw()});
  if(!r.ok) alert(t('err') + (r.error||'?'));
  else paintRunControls();
}

async function stopLecture(){
  if(lecState() !== 'running') return;
  if(!confirm(t('stopConfirm'))) return;
  const id = curId || localStorage.getItem(LSKEY);
  if(!id) return;
  const r = await api({action:'stop', s:id, pw:getPw()});
  if(!r.ok) alert(t('err') + (r.error||'?'));
  else {
    paintRunControls();
    /* Beendet = exportieren: JSON-Download direkt anbieten */
    await exportJson(id);
  }
}

/* Neuentscheidung aller Studenten anfordern (60 s) bzw. Abstimmung eröffnen (60 s) */
async function testAsk(){
  const id = curId || localStorage.getItem(LSKEY);
  if(!id) return;
  const r = await api({action:'test', s:id, pw:getPw()});
  if(!r.ok) alert(t('err') + (r.error||'?'));
}
async function startVote(){
  const id = curId || localStorage.getItem(LSKEY);
  if(!id) return;
  const sel = document.getElementById('vpacksel');
  const pack = sel && !sel.classList.contains('hidden') ? +sel.value : 0;
  const r = await api({action:'vote', s:id, pw:getPw(), pack});
  if(!r.ok) alert(t('err') + (r.error||'?'));
}
/* Laufende Abstimmung: Sekunden-Countdown, Verlängerung um 1 Minute,
   sofortiger Abschluss mit Ergebnis */
async function voteExtend(){
  const id = curId || localStorage.getItem(LSKEY);
  if(!id) return;
  const r = await api({action:'voteext', s:id, pw:getPw()});
  if(!r.ok) alert(t('err') + (r.error||'?'));
}
async function voteStopNow(){
  const id = curId || localStorage.getItem(LSKEY);
  if(!id) return;
  const r = await api({action:'votestop', s:id, pw:getPw()});
  if(!r.ok) alert(t('err') + (r.error||'?'));
}
setInterval(() => { // Countdown der laufenden Abstimmung (Sekunden)
  const ctl = document.getElementById('voteCtl');
  if(!ctl) return;
  const vu = session && !archive ? session.vote_until : 0;
  const rem = vu ? Math.max(0, vu - Math.floor(Date.now()/1000)) : 0;
  ctl.classList.toggle('hidden', !rem);
  if(rem) document.getElementById('voteRem').textContent = rem;
}, 250);
/* Optionspaket-Dropdown füllen (vor dem Abstimmen-Knopf) */
function fillPackSel(){
  const sel = document.getElementById('vpacksel');
  if(!sel) return;
  const packs = (session && session.vote_packs) || [];
  sel.innerHTML = '';
  if(!packs.length){ sel.classList.add('hidden'); return; }
  const free = document.createElement('option');
  free.value = '0'; free.textContent = LANG === 'de' ? 'Frei: Ziffern 1–9 · 0 = Enthaltung' : 'Free: digits 1–9 · 0 = abstain';
  sel.appendChild(free);
  packs.forEach((p, i) => {
    const o = document.createElement('option');
    o.value = String(i + 1);
    o.textContent = p.title;
    sel.appendChild(o);
  });
  sel.classList.remove('hidden');
}

async function exportJson(idIn){
  const id = idIn || archiveId || curId || localStorage.getItem(LSKEY);
  const pw = getPw();
  if(!id || !pw){ alert(t('expPw')); return; }
  const r = await fetch(location.pathname, {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({action:'export', s:id, pw, lang:LANG})
  });
  if(!r.ok){ alert(t('expFail')); return; }
  const cd = r.headers.get('Content-Disposition') || '';
  const name = (cd.match(/filename="([^"]+)"/) || [,'session.json'])[1];
  const blob = await r.blob();
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob); a.download = name;
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(()=>URL.revokeObjectURL(a.href), 5000);
}

async function logout(){
  if(!confirm(t('logoutConfirm'))) return;
  localStorage.removeItem(LSPW);
  localStorage.removeItem(LSKEY);
  location.reload();
}

async function restart(){
  /* Rein lokal: beendet die aktuelle Ansicht. Die Session-Datei bleibt als
     Archiv in zzz-data/ erhalten und taucht in der Historie wieder auf. */
  if(!confirm(t('restartConfirm'))) return;
  localStorage.removeItem(LSKEY);
  if(es) es.close();
  location.reload();
}

/* ---------------- Diagramm, Töne & Chat ---------------- */

/* Töne: kurzer heller "Bing" (Join), tiefer längerer "Bong" (OUT) */
let audioCtx = null;
function ensureAudio(){
  if(!audioCtx) audioCtx = new (window.AudioContext||window.webkitAudioContext)();
  if(audioCtx.state === 'suspended') audioCtx.resume();
}
function bing(){ // kurz + hell
  ensureAudio(); const t = audioCtx.currentTime;
  [[880,0,0.12],[1318.5,0.09,0.18]].forEach(([f,off,d])=>{
    const o = audioCtx.createOscillator(), g = audioCtx.createGain();
    o.type='sine'; o.frequency.value=f;
    g.gain.setValueAtTime(0.25, t+off);
    g.gain.exponentialRampToValueAtTime(0.001, t+off+d+0.15);
    o.connect(g).connect(audioCtx.destination); o.start(t+off); o.stop(t+off+d+0.2);
  });
}
function bong(){ // deutlich tiefer, länger
  ensureAudio(); const t = audioCtx.currentTime;
  const o = audioCtx.createOscillator(), g = audioCtx.createGain();
  o.type='sine';
  o.frequency.setValueAtTime(165, t);
  o.frequency.exponentialRampToValueAtTime(70, t+0.7);
  g.gain.setValueAtTime(0.45, t);
  g.gain.exponentialRampToValueAtTime(0.001, t+1.0);
  o.connect(g).connect(audioCtx.destination); o.start(t); o.stop(t+1.1);
}
function fanfare(){ // kurzes Fanfaren-Signal: C5-E5-G5-C6
  ensureAudio(); const t = audioCtx.currentTime;
  const seq = [[523.25,0],[659.25,0.11],[783.99,0.22],[1046.50,0.33]];
  seq.forEach(([f,off])=>{
    const o = audioCtx.createOscillator(), g = audioCtx.createGain();
    o.type='square'; o.frequency.value=f;
    g.gain.setValueAtTime(0.0001, t+off);
    g.gain.linearRampToValueAtTime(0.15, t+off+0.02);
    g.gain.setValueAtTime(0.15, t+off+0.08);
    g.gain.exponentialRampToValueAtTime(0.001, t+off+0.13);
    o.connect(g).connect(audioCtx.destination); o.start(t+off); o.stop(t+off+0.18);
  });
}
let fanfared = false; // einmal pro Vorlesung, wenn die letzten 10% erreicht sind
let alarmedStart = false, alarmedEnd = false; // Alarme für geplante Start-/Endzeit
function alarmTones(){ // drei gleiche Töne (880 Hz), ggf. später auch für geplante Zeiten
  ensureAudio(); const t = audioCtx.currentTime;
  [0, 0.45, 0.90].forEach(off => {
    const o = audioCtx.createOscillator(), g = audioCtx.createGain();
    o.type='square'; o.frequency.value=880;
    g.gain.setValueAtTime(0.0001, t+off);
    g.gain.linearRampToValueAtTime(0.20, t+off+0.02);
    g.gain.setValueAtTime(0.20, t+off+0.22);
    g.gain.exponentialRampToValueAtTime(0.001, t+off+0.30);
    o.connect(g).connect(audioCtx.destination); o.start(t+off); o.stop(t+off+0.35);
  });
}

/* Neue Events verarbeiten: Töne + Chat-Bubbles */
let processed = 0, silent = true;
let filterStu = null;   // aktiver Studenten-Filter im Chat
let selRange = null;    // aktiver Zeitraum-Filter (aus Diagramm-Ziehung)
let zoomT = null;       // aktiver X-Zoom [t1, t2] im Diagramm (null = Gesamtansicht)
let dragStart = null, dragX = null; // laufende Finger-/Maus-Ziehung im Diagramm
let probeT = null;  // Archiv: Zeitposition der gelben Sondenlinie (unter dem Finger)
let chartMap = null;    // x<->t-Mapping des zuletzt gezeichneten Diagramms

function chatTitle(){
  const h = document.querySelector('#chat h3');
  if(!h) return;
  h.textContent = filterStu
    ? t('chatStu')
    : selRange
      ? t('chatRange')
      : (archive ? t('msgsArch') : t('msgs'));
}
function applyFilterEl(el){
  if(el.tagName === 'H3') return;
  if(filterStu){ el.style.display = (el.dataset.stu === filterStu) ? '' : 'none'; return; }
  if(selRange){ const t = +el.dataset.t; el.style.display = (t >= selRange.t1 && t <= selRange.t2) ? '' : 'none'; return; }
  el.style.display = '';
}
function resetAll(){
  filterStu = null; selRange = null; zoomT = null;
  document.querySelectorAll('#chat > *').forEach(el => { el.style.display = ''; });
  chatTitle();
}
/* Archiv: gelbe Linie im Chat genau zwischen den Nachrichten an der Position,
   an der sich die gelbe Sondenlinie im Diagramm gerade befindet */
function updateChatMark(){
  const chat = document.getElementById('chat');
  if(!chat) return;
  const old = chat.querySelector('.chatmark'); if(old) old.remove();
  if(!archive || probeT === null) return;
  const mark = document.createElement('div');
  mark.className = 'chatmark';
  let ref = null;
  /* Chat ist zeitlich absteigend sortiert (neueste oben): alle Elemente mit
     t > probeT stehen vor der Marke, danach folgen die älteren */
  for(const el of chat.children){
    if(el.classList && el.classList.contains('chatmark')) continue;
    const tEl = el.dataset ? el.dataset.t : null;
    if(tEl !== undefined && tEl !== '' && +tEl <= probeT){ ref = el; break; }
  }
  chat.insertBefore(mark, ref); // null -> hinten anfügen
}

/* Klick im Chat: Eintrag -> Studenten-Verlauf; erneut klicken -> zurück */
document.getElementById('chat').addEventListener('click', ev => {
  const el = ev.target.closest('[data-stu]');
  if(!el) return;
  if(filterStu){ resetAll(); render(); return; }
  selRange = null;                       // Zeitraum-Modus wird vom Studenten-Modus abgelöst
  zoomT = null;
  filterStu = el.dataset.stu;
  document.querySelectorAll('#chat > *').forEach(applyFilterEl);
  chatTitle(); render();
});

/* Diagramm: horizontal überstreichen -> Zeitraum wählen; einfacher Klick -> Modus verlassen */
function xToT(x){
  if(!chartMap) return 0;
  const m = chartMap;
  const rel = Math.min(1, Math.max(0, (x - m.l) / m.pw));
  return m.t0 + rel * m.xmax;
}
document.getElementById('chart').addEventListener('pointerdown', e => {
  dragStart = e.offsetX; dragX = e.offsetX;
  if(archive && chartMap) probeT = xToT(e.offsetX);
});
document.getElementById('chart').addEventListener('pointermove', e => {
  if(dragStart === null) return;
  dragX = e.offsetX;
  if(archive && chartMap) probeT = xToT(e.offsetX); // gelbe Linie folgt dem Finger
  if(!filterStu) render(); // Band-Vorschau live
});
document.getElementById('chart').addEventListener('pointerup', e => {
  if(dragStart === null) return;
  if(archive && chartMap) probeT = xToT(e.offsetX); // Position bleibt liegen
  const moved = Math.abs(e.offsetX - dragStart) > 6;
  const x0 = Math.min(dragStart, e.offsetX), x1 = Math.max(dragStart, e.offsetX);
  dragStart = null; dragX = null;
  if(!moved){ // einfacher Klick: Auswahl/Zoom verlassen
    if(filterStu || selRange || zoomT){ resetAll(); render(); }
    else if(archive) render(); // Antippen im Archiv: Sondenlinie setzen
    return;
  }
  if(filterStu) return; // im Studenten-Modus keine Zeitraum-Ziehung
  filterStu = null;
  selRange = {t1: xToT(x0), t2: xToT(x1)};
  zoomT = [Math.min(selRange.t1, selRange.t2), Math.max(selRange.t1, selRange.t2)];
  document.querySelectorAll('#chat > *').forEach(applyFilterEl);
  chatTitle(); render();
});
document.getElementById('chart').addEventListener('pointerleave', () => { dragStart = null; dragX = null; });

function processEvents(d){
  const evs = (d.events||[]).slice().sort((a,b)=>a.t-b.t);
  const chat = document.getElementById('chat');
  const t0c = d.sched_start || d.started_at; // gleicher Anker wie im Diagramm
  /* Neueste Nachricht oben: jedes neue Element direkt unter den Titel einfügen */
  const pushTop = el => { chat.insertBefore(el, chat.children[1] || null); applyFilterEl(el); };
  for(; processed < evs.length; processed++){
    const e = evs[processed];
    const off = t0c ? Math.max(0, e.t - t0c) : 0;
    const mm = Math.floor(off/60); // volle Minuten, keine Sekunden
    if(!silent){
      if(e.kind === 'join') bing();
      if(e.kind === 'out')  bong();
    }
    if(e.kind === 'join' || e.kind === 'leave'){
      const sys = document.createElement('div');
      sys.className = 'sys';
      sys.dataset.stu = e.s; sys.dataset.t = e.t;
      sys.textContent = e.kind==='join' ? t('joinMsg')+mm+t('minEnd') : t('leaveMsg')+mm+t('minEnd');
      pushTop(sys);
    } else if(e.kind === 'warn' || e.kind === 'decided' || e.kind === 'voteopen' || e.kind === 'voteclose'){
      /* blaue Systemkästen: Neuentscheidung / Abstimmung, mit Zusammenfassung */
      const box = document.createElement('div');
      box.className = 'sysbox';
      box.dataset.t = e.t;
      let txt = '';
      if(e.kind === 'warn')
        txt = (e.by === 'lecturer' ? t('sysWarnLec') : t('sysWarnAuto')) + t('cntFmt')(e.cnt.in, e.cnt.out, e.cnt.undef);
      else if(e.kind === 'decided')
        txt = t('sysDecided') + t('cntFmt')(e.cnt.in2, e.cnt.out2, e.cnt.undef2);
      else if(e.kind === 'voteopen')
        txt = t('sysVoteOpen');
      else { // voteclose — Diagramm zuerst (Spannung), Zusammenfassung erst danach
        txt = (e.mode === 'all' ? t('sysVoteAll') + ' '
             : e.mode === 'manual' ? t('sysVoteStop') + ' ' : '') + t('sysVoteRes');
      }
      if(e.kind !== 'voteclose') box.textContent = txt;
      if(e.kind === 'voteclose'){
        /* Titel des Optionspakets ganz oben */
        const pk = +(e.pack || 0);
        const packObj = pk > 0 ? ((session && session.vote_packs) || [])[pk - 1] : null;
        if(packObj){
          const vt = document.createElement('div');
          vt.className = 'vtitle'; vt.textContent = packObj.title;
          box.appendChild(vt);
        }
        /* Beteiligung sofort anzeigen (verrät noch nichts über das Ergebnis) */
        const turn = document.createElement('div');
        turn.className = 'vturn';
        turn.textContent = t('sysTurnout')(+(e.voters||0), +(e.present||0));
        box.appendChild(turn);
      }
      if(e.kind === 'voteclose' && e.votes && Object.keys(e.votes).length){
        /* Mini-Balkendiagramm: aufsteigend sortiert, die schlechtesten Werte
           erscheinen zuerst, bessere Ergebnisse decken sich nach und nach auf.
           Erst nach der letzten Aufdeckung erscheint die Text-Zusammenfassung. */
        const pk2 = +(e.pack || 0);
        const optsOf = pk2 > 0 ? (((session && session.vote_packs) || [])[pk2 - 1] || {}).opts : null;
        const optLabel = v => (optsOf && optsOf[v - 1]) ? optsOf[v - 1]
          : (v === 0 ? t('abstain') : String(v));
        const entries = Object.keys(e.votes).map(v => [+v, e.votes[v]]);
        const max = Math.max(1, ...entries.map(x => x[1]));
        const total = +(e.voters || entries.reduce((s,x) => s+x[1], 0));
        const pct = c0 => total ? Math.round(c0/total*100) : 0;
        entries.sort((a,b) => a[1] - b[1]);
        const chart = document.createElement('div');
        chart.className = 'vchart';
        entries.forEach(([v,c],idx) => {
          const lbl = optLabel(v);
          const hue = (v%10)*36;
          const row = document.createElement('div');
          row.className = 'vrow';
          const lab = document.createElement('span'); lab.className='vlab'; lab.textContent = lbl;
          if(optsOf) lab.title = lbl;
          const track = document.createElement('span'); track.className='vtrack';
          const bar = document.createElement('span'); bar.className='vbar';
          bar.style.setProperty('--w', Math.round(c/max*100) + '%');
          bar.style.setProperty('--d', (idx*0.45) + 's');
          bar.style.background = 'hsl('+hue+',70%,55%)';
          track.appendChild(bar);
          const cnt = document.createElement('span'); cnt.className='vcnt';
          cnt.textContent = c + ' · ' + pct(c) + '%';
          row.appendChild(lab); row.appendChild(track); row.appendChild(cnt);
          chart.appendChild(row);
        });
        box.appendChild(chart);
        /* Text-Zusammenfassung erst nach dem letzten Balken sichtbar */
        const sum = document.createElement('div');
        sum.className = 'vsum';
        sum.style.setProperty('--d', (entries.length*0.45 + 0.9) + 's');
        const parts = Object.keys(e.votes).sort((a,b)=>(+a)-(+b));
        sum.textContent = txt + (parts.length ? parts.map(v =>
          optLabel(+v) + ': ' + e.votes[v] + ' (' + pct(e.votes[v]) + '%)').join(' · ') : t('noVotes'));
        box.appendChild(sum);
      }
      if(e.kind === 'voteclose' && !(e.votes && Object.keys(e.votes).length)){
        const none = document.createElement('div');
        none.textContent = txt + t('noVotes');
        box.appendChild(none);
      }
      pushTop(box);
    } else if(e.kind === 'vote'){
      /* Einzelne Stimmen erscheinen nicht im Chat, nur im Diagramm/Export */
    } else if(e.kind === 'eval'){
      /* Bewertungsantwort: gelbe Bubble, wie IN/OUT mit dem Studenten auswählbar */
      const b = document.createElement('div');
      b.className = 'bubble eval';
      b.dataset.stu = e.s; b.dataset.t = e.t;
      b.innerHTML = '<div class="meta">📝 '+t('evalLbl')+' · '+mm+' min</div>' +
        escapeHtml(e.qq||'') +
        (e.a ? '<br>→ <b>' + escapeHtml(e.a) + '</b>' : '') +
        (e.msg ? '<br>💬 ' + escapeHtml(e.msg) : '');
      pushTop(b);
    } else {
      /* Jede IN/OUT/undef-Meldung erscheint im Chat — auch ohne Text und ohne Emoji */
      const b = document.createElement('div');
      b.className = 'bubble ' + e.kind;
      b.dataset.stu = e.s; b.dataset.t = e.t;
      const lbl = e.kind==='out' ? '❌ OUT' : (e.kind==='undef' ? '❔ UNDEF' : '✅ IN');
      b.innerHTML = '<div class="meta">'+lbl+(e.slide ? ' · '+t('slideLbl')+' '+e.slide : '')+' · '+mm+' min</div>' +
        escapeHtml(e.emoji ? e.emoji+' ' : '') + escapeHtml(e.msg);
      pushTop(b);
    }
  }
  chat.scrollTop = 0; // neueste Nachricht bleibt oben sichtbar
  silent = false;
}
function escapeHtml(s){ const d=document.createElement('div'); d.textContent=s||''; return d.innerHTML; }

/* ---------- Pro-Visualisierungen: Tortendiagramm & Strichmännchen ---------- */
function liveCounts(){
  const st = session.students || {};
  let cIn = 0, cOut = 0, cUn = 0, j = 0;
  for(const k in st){ const s = st[k]; if(!s || s.left) continue; j++;
    if(s.st === 'in') cIn++; else if(s.st === 'out') cOut++; else cUn++; }
  return {in:cIn, out:cOut, undef:cUn, joined:j};
}
function drawPie(ctx, W, H, cnt){
  ctx.clearRect(0,0,W,H);
  const cx = W/2, cy = H/2 - 16, R = Math.max(50, Math.min(W,H)/2 - 70);
  const parts = [['in', cnt.in, '#2ecc71'], ['undef', cnt.undef, '#f1c40f'], ['out', cnt.out, '#e74c3c']];
  const tot = cnt.in + cnt.undef + cnt.out;
  if(!tot){
    ctx.fillStyle = '#8b98a5'; ctx.font = '16px system-ui'; ctx.textAlign = 'center';
    ctx.fillText(t('chartWait'), cx, cy); return;
  }
  let a = -Math.PI/2;
  for(const [k, v, col] of parts){
    if(!v) continue;
    const a2 = a + 2*Math.PI*v/tot, mid = (a+a2)/2;
    ctx.beginPath(); ctx.moveTo(cx,cy); ctx.arc(cx,cy,R,a,a2); ctx.closePath();
    ctx.fillStyle = col; ctx.fill();
    ctx.strokeStyle = '#0c1014'; ctx.lineWidth = 3; ctx.stroke();
    /* Anzahl je Teil als Beschriftung im Kreisausschnitt */
    ctx.fillStyle = '#0c1014'; ctx.textAlign = 'center';
    ctx.font = 'bold ' + Math.min(30, Math.max(16, R/4|0)) + 'px system-ui';
    ctx.fillText(String(v), cx + Math.cos(mid)*R*0.62, cy + Math.sin(mid)*R*0.62 + 9);
    a = a2;
  }
  /* Legende unter dem Kuchen: Farbfeld + Anzahl je Zustand */
  ctx.font = 'bold 13px system-ui'; ctx.textAlign = 'left';
  let x = 14;
  for(const [txt, col] of [['IN · '+cnt.in,'#2ecc71'], ['undef · '+cnt.undef,'#f1c40f'], ['OUT · '+cnt.out,'#e74c3c']]){
    ctx.fillStyle = col; ctx.fillRect(x, H-32, 14, 14);
    ctx.fillStyle = '#e8edf2'; ctx.fillText(txt, x+19, H-20);
    x += 19 + ctx.measureText(txt).width + 20;
  }
}
/* Ein Strichmännchen: Kopf + Rumpf + Arme + Beine; walk=true = auf dem Weg nach draußen */
function man(x, y, c, walk){
  const legs = walk
    ? 'M'+(x-9)+' '+(y+18)+' l-9 13 M'+(x+9)+' '+(y+18)+' l10 9'
    : 'M'+(x-8)+' '+(y+18)+' v13 M'+(x+8)+' '+(y+18)+' v13';
  return '<g stroke="'+c+'" stroke-width="3.4" fill="none" stroke-linecap="round">'+
    '<circle cx="'+x+'" cy="'+(y-24)+'" r="8.5" fill="'+c+'" stroke="none"/>'+
    '<path d="M'+x+' '+(y-15)+' v21 M'+(x-11)+' '+(y-7)+' h22 '+legs+'"/></g>';
}
function drawFigures(el, cnt){
  const W = 760, H = 340, gap = 48;
  const defs = [['undef', cnt.undef, '#f1c40f'], ['in', cnt.in, '#2ecc71'], ['out', cnt.out, '#e74c3c']];
  const act = defs.filter(z => z[1] > 0);
  let svg = '';
  if(!act.length){
    svg = '<text x="'+(W/2)+'" y="'+(H/2)+'" text-anchor="middle" font-size="18" fill="#8b98a5">'+t('chartWait')+'</text>';
  } else {
    /* Zielflächen: Breite anteilig nach Gruppenzahl (nur eine Gruppe -> weit ausgedehnt) */
    const inner = W - 2*gap;
    const totU = act.reduce((s,z) => s+z[1], 0) || 1;
    let widths = act.map(z => Math.max(150, inner*z[1]/totU));
    const wsum = widths.reduce((a,b) => a+b, 0);
    if(wsum > inner) widths = widths.map(w => w*inner/wsum);
    let x = gap;
    const cy = H/2 + 34, ry = 84;
    act.forEach((z, i) => {
      const w = widths[i];
      /* elliptische Sammelfläche */
      svg += '<ellipse cx="'+(x+w/2)+'" cy="'+cy+'" rx="'+(w/2)+'" ry="'+ry+'" fill="'+z[2]+'" opacity="0.13" stroke="'+z[2]+'" stroke-opacity="0.5" stroke-dasharray="6 5"/>';
      /* Anzahl groß über der Fläche — nur, wenn es Mitglieder gibt */
      svg += '<text x="'+(x+w/2)+'" y="'+(cy-ry-16)+'" text-anchor="middle" font-size="42" font-weight="800" fill="'+z[2]+'">'+z[1]+'</text>';
      /* Strichmännchen in Reihen (max. 36 je Zone); OUT läuft mit Schritt-Pose weg */
      const perRow = Math.max(3, Math.min(6, Math.ceil(z[1])));
      const sp = Math.min(42, (w-24)/Math.min(z[1], perRow));
      for(let n = 0; n < z[1] && n < 36; n++){
        const r = Math.floor(n/perRow);
        const inRow = Math.min(z[1]-r*perRow, perRow);
        const px = x + w/2 + ((n%perRow) - (inRow-1)/2)*sp;
        const py = cy + 20 - r*54;
        svg += man(px, py, z[2], z[0] === 'out');
      }
      x += w + gap*0.7;
    });
  }
  el.innerHTML = '<svg viewBox="0 0 '+W+' '+H+'" style="width:100%;max-width:760px">'+svg+'</svg>';
}
/* Kuchen/Strichmännchen: aktueller Stand statt Zeitverlauf — Timer & Statuszeile bleiben */
function renderSimple(lv){
  const c = document.getElementById('chart'), fig = document.getElementById('figwrap');
  const cnt = liveCounts();
  const started = !!session.started_at;
  const statEl = document.getElementById('stat');
  if(statEl) statEl.textContent = (started ? '' : t('statNot')) +
    t('statLive')(cnt.joined, cnt.in, cnt.out, cnt.undef);
  const bt = document.getElementById('bigtime');
  if(bt){
    bt.classList.remove('hidden');
    const anchor = session.sched_start || session.started_at;
    const now = session.stopped_at || Math.floor(Date.now()/1000);
    const elapsed = anchor ? Math.max(0, now - anchor) : 0;
    const planned = session.planned_min*60;
    const stopped = !!session.stopped_at;
    const eMin = Math.floor(elapsed/60)*60, remDisp = Math.max(0, planned - eMin);
    if(elapsed > planned){
      const om = Math.ceil((elapsed-planned)/60)*60;
      bt.innerHTML = '<span>'+fmt(eMin)+'</span><span class="bsep">—</span><span class="red blink">+'+fmt(om)+'</span>';
    } else if(elapsed >= planned*0.9){
      bt.innerHTML = '<span>'+fmt(eMin)+'</span><span class="bsep">—</span><span class="'+(stopped?'gray':'yellow')+'">'+fmt(remDisp)+'</span>';
    } else {
      bt.innerHTML = '<span>'+fmt(eMin)+'</span><span class="bsep">—</span><span class="'+(stopped?'gray':'')+'">'+fmt(remDisp)+'</span>';
    }
    bt.classList.remove('arch');
  }
  if(lv === 'pie'){
    fig.classList.add('hidden'); c.classList.remove('hidden');
    const dpr = window.devicePixelRatio || 1, W = c.clientWidth || 600, H = c.clientHeight || 420;
    c.width = W*dpr; c.height = H*dpr;
    const ctx = c.getContext('2d'); ctx.setTransform(dpr,0,0,dpr,0,0);
    drawPie(ctx, W, H, cnt);
  } else {
    c.classList.add('hidden'); fig.classList.remove('hidden');
    drawFigures(fig, cnt);
  }
}

function render(){
  if(!session) return;
  /* Pro-Visualisierung: Tortendiagramm oder Strichmännchen (live); Archiv bleibt Zeitverlauf */
  const lv = session.lecview || 'chart';
  if(!archive && (lv === 'pie' || lv === 'figures')){ renderSimple(lv); return; }
  const figEl = document.getElementById('figwrap'); if(figEl) figEl.classList.add('hidden');
  const cvEl = document.getElementById('chart'); if(cvEl) cvEl.classList.remove('hidden');
  const c = document.getElementById('chart');
  const dpr = window.devicePixelRatio || 1;
  const W = c.clientWidth, H = c.clientHeight;
  c.width = W*dpr; c.height = H*dpr;
  const ctx = c.getContext('2d');
  ctx.setTransform(dpr,0,0,dpr,0,0);
  ctx.clearRect(0,0,W,H);

  const legB = W > 620;                    // zweite Legendenzeile (Linienerklärung)
  const M = {l:46, r:14, t:34, b: legB ? 96 : 78}; // unten Platz für Minuten + Legende
  const pw = W-M.l-M.r, ph = H-M.t-M.b;
  const stopped = !!session.stopped_at;
  const now = archive ? archEnd
    : (session.stopped_at ? session.stopped_at : Math.floor(Date.now()/1000));
  /* Zeit-Anker: geplante Startzeit (gelbe Linie läuft ab Alarm), sonst echter Start.
     Ohne beides steht die gelbe Linie bei 0, bis Start gedrückt wird. */
  const anchor = session.sched_start || session.started_at || null;
  const started = !!session.started_at;
  const t0 = anchor || now;
  const planned = session.planned_min*60;
  const elapsed = anchor ? Math.max(0, now - anchor) : 0;
  const xmax = Math.max(elapsed, planned, 60); // wächst bei Zeitüberschreitung

  /* X-Zoom: eingezoomter Zeitbereich (absolute Zeiten), sonst Gesamtansicht.
     Kurven, Achsen und Balken werden nur für den sichtbaren Bereich gezeichnet. */
  const zoomOn = !!zoomT && !filterStu;
  const vs  = zoomOn ? zoomT[0] : t0;                  // linke Kante (absolut)
  const vlen = zoomOn ? Math.max(30, zoomT[1]-zoomT[0]) : xmax;

  /* Replay aller Events -> Verläufe joined / IN / OUT / undef; ymax = Peak der Studenten */
  /* Startzustand beim Beitritt je Modus (Alt-Sessions ohne Feld: nach start_in) */
  const startIn = (session.ask_mode === 'auto' || session.ask_mode === 'ondemand')
    ? false : (session.start_in !== false);
  const evs = (session.events||[]).slice().sort((a,b)=>a.t-b.t);
  let joined = 0, peakJoined = 0;
  const stu = {};   // token -> 'in' | 'out' | 'undef'
  const pts = [{t:t0, joined:0, in:0, out:0, undef:0, kind:null}];
  for(const e of evs){
    if(e.kind === 'join'){ joined++; stu[e.s] = startIn ? 'in' : 'undef'; }
    else if(e.kind === 'leave'){ joined = Math.max(0, joined-1); delete stu[e.s]; }
    else if(e.kind === 'in' || e.kind === 'out' || e.kind === 'undef'){ stu[e.s] = e.kind; }
    /* 'vote' u.a. beeinflussen die Kurven nicht */
    let cIn=0, cOut=0, cUn=0;
    for(const k in stu){ if(stu[k]==='in') cIn++; else if(stu[k]==='out') cOut++; else cUn++; }
    pts.push({t:e.t, joined:Math.max(0,joined), in:cIn, out:cOut, undef:cUn,
              kind:e.kind, s:e.s, val:e.val||0});
    peakJoined = Math.max(peakJoined, joined);
  }
  const ymax = Math.max(1, peakJoined); // Y-Achse passt sich der Studentenzahl an (kein Mindestmaß 2)

  /* Abstimmungsfenster: von voteopen bis voteclose (60 s bzw. vorzeitig) —
     Stimmbalken werden nur innerhalb dieser Bänder gezeichnet und bleiben
     auch im Archiv erhalten. */
  const voteBands = [];
  let vbOpen = null;
  for(const e of evs){
    if(e.kind === 'voteopen') vbOpen = [e.t, null];
    else if(e.kind === 'voteclose' && vbOpen){ vbOpen[1] = e.t; voteBands.push(vbOpen); vbOpen = null; }
  }
  if(vbOpen) voteBands.push([vbOpen[0], archive ? archEnd : Math.floor(Date.now()/1000)]);

  // Hintergrundzonen (letzte 10 % orange, Überziehung rot) — gezeichnet erst nach xOf,
  // damit sie auch im Zoom korrekt beschnitten werden (siehe unten).

  // Gitter + y-Achse
  ctx.strokeStyle = '#2a323c'; ctx.fillStyle = '#8b98a5';
  ctx.font = '11px system-ui'; ctx.textAlign='right';
  const steps = Math.min(ymax, 8);
  for(let i=0;i<=steps;i++){
    const v = Math.round(ymax*i/steps), y = M.t + ph - ph*v/ymax;
    ctx.beginPath(); ctx.moveTo(M.l,y); ctx.lineTo(M.l+pw,y); ctx.stroke();
    ctx.fillText(v, M.l-8, y+4);
  }
  // x-Achse: lesbare Minuten-Beschriftung des sichtbaren Bereichs (auch im Zoom)
  ctx.textAlign='center';
  const nice = [1,2,5,10,15,20,30,60,90,120];
  const rough = (vlen/60) / 10; // ~10 Beschriftungen anstreben
  const tickMin = nice.find(n => n >= rough) || 120;
  const mFrom = Math.max(0, Math.ceil(((vs - t0)/60) / tickMin) * tickMin);
  const mTo = (vs - t0)/60 + vlen/60;
  for(let m = mFrom; m <= mTo; m += tickMin){
    const x = M.l + pw*((t0 + m*60) - vs)/vlen;
    if(x < M.l-1 || x > M.l+pw+1) continue;
    const lab = m===0 ? '0 min' : (m>=60 && m%60===0 ? (m/60)+' h' : m+' min');
    // senkrecht gestellte Beschriftung: Text läuft vom Achsenrand nach oben
    ctx.save();
    ctx.translate(x, legB ? H-48 : H-28);
    ctx.rotate(-Math.PI/2);
    ctx.textAlign = 'left';
    ctx.fillText(lab, 0, 3);
    ctx.restore();
  }

  const xOf = t => M.l + pw*Math.max(0, Math.min(t-vs, vlen))/vlen;
  const yOf = v => M.t + ph - ph*v/ymax;

  // Hintergrundzonen: letzte 10 % orange, Überziehung rot — im Zoom beschnitten
  {
    const clampX = x => Math.max(M.l, Math.min(x, M.l+pw));
    const x80 = clampX(xOf(t0 + planned*0.9)), xEnd = clampX(xOf(t0 + planned));
    if(xEnd > x80){ ctx.fillStyle = 'rgba(243,156,18,0.10)'; ctx.fillRect(x80, M.t, xEnd-x80, ph); }
    if(xEnd < M.l+pw){ ctx.fillStyle = 'rgba(231,76,60,0.10)';
      ctx.fillRect(Math.max(xEnd,M.l), M.t, M.l+pw-Math.max(xEnd,M.l), ph); }
  }

  // Abstimmungsfenster als blaue Bänder hinter allen Kurven (im Zoom beschnitten)
  for(const b of voteBands){
    const cx = x => Math.max(M.l, Math.min(x, M.l+pw));
    const bx1 = cx(xOf(b[0])), bx2 = cx(xOf(b[1] !== null ? b[1] : b[0]+60));
    if(bx2 > bx1){ ctx.fillStyle = 'rgba(52,152,219,0.10)'; ctx.fillRect(bx1, M.t, bx2-bx1, ph); }
  }
  chartMap = {t0: vs, xmax: vlen, pw, l: M.l}; // für xToT (Zeitraum-Ziehung, Band-Vorschau)

  // Auswahl-Band: gesetzter Zeitraum oder live Vorschau der Ziehung
  let band = null;
  if(selRange) band = [selRange.t1, selRange.t2];
  else if(dragStart !== null && !filterStu && Math.abs(dragX - dragStart) > 6)
    band = [xToT(Math.min(dragStart, dragX)), xToT(Math.max(dragStart, dragX))];
  if(band){
    const bx1 = xOf(band[0]), bx2 = xOf(band[1]);
    ctx.fillStyle = 'rgba(255,255,255,0.09)';
    ctx.fillRect(bx1, M.t, bx2-bx1, ph);
    ctx.strokeStyle = 'rgba(255,255,255,0.4)';
    ctx.beginPath(); ctx.moveTo(bx1,M.t); ctx.lineTo(bx1,M.t+ph); ctx.stroke();
    ctx.beginPath(); ctx.moveTo(bx2,M.t); ctx.lineTo(bx2,M.t+ph); ctx.stroke();
  }

  // Vertikale Balken: grün in/join, rot out/leave, grau undef, Stimmen farbig je Ziffer
  const blink = 0.40 + 0.35*Math.abs(Math.sin(Date.now()/280)); // Puls für den markierten Studenten
  for(const p of pts){
    if(!p.kind) continue;
    if(xOf(p.t) < M.l-3 || xOf(p.t) > M.l+pw+3) continue; // außerhalb des Zoomfensters
    let col;
    if(p.kind === 'vote') col = null; // Stimmen unten gesondert
    else if(p.kind === 'undef') col = '139,152,165';
    else col = (p.kind==='in'||p.kind==='join') ? '46,204,113' : (p.kind==='eval' ? '241,196,15' : '231,76,60');
    if(p.kind === 'vote'){
      /* Stimme: farbiger Balken mit Ziffer — nur innerhalb des Abstimmungsfensters */
      if(!voteBands.some(b => p.t >= b[0] && p.t <= (b[1] !== null ? b[1] : b[0]+60))) continue;
      const hue = (p.val%10)*36;
      ctx.fillStyle = 'hsla('+hue+',70%,55%,0.45)';
      ctx.fillRect(xOf(p.t)-2, M.t, 4, ph);
      ctx.fillStyle = 'hsl('+hue+',70%,70%)';
      ctx.font = 'bold 10px system-ui'; ctx.textAlign = 'center';
      ctx.fillText(String(p.val), xOf(p.t), M.t-4);
      ctx.font = '11px system-ui';
      continue;
    }
    if(p.kind === 'warn' || p.kind === 'decided' || p.kind === 'voteopen' || p.kind === 'voteclose'){
      /* blaue Markierung für Neuentscheidung / Abstimmung */
      let a = 0.30;
      if(filterStu) a = 0.06;
      ctx.fillStyle = 'rgba(52,152,219,'+a+')';
      ctx.fillRect(xOf(p.t)-1.5, M.t, 3, ph);
      continue;
    }
    let a = 0.25;
    if(filterStu) a = (p.s === filterStu) ? blink : 0.06; // seine Balken blinken, Rest verblasst
    ctx.fillStyle = 'rgba('+col+','+a+')';
    ctx.fillRect(xOf(p.t)-2, M.t, 4, ph);
  }

  // Gelbe Linie: live = aktuelle Zeit (läuft ab Anker); im Archiv = Sondenlinie
  // unter dem Finger bzw. an der zuletzt gewählten Position.
  // Halbtransparent wie die blauen Linien, damit sie hinter den Kurven verläuft.
  ctx.strokeStyle = 'rgba(241,196,15,0.6)';
  ctx.lineWidth = 2;
  const xYellow = archive ? (probeT !== null ? xOf(probeT) : null) : xOf(t0 + elapsed);
  if(xYellow !== null && xYellow >= M.l && xYellow <= M.l+pw){
    ctx.beginPath(); ctx.moveTo(xYellow,M.t); ctx.lineTo(xYellow,M.t+ph); ctx.stroke();
  }
  ctx.lineWidth = 1;

  // Gelbe gestrichelte Linien: geplante Start-/Endzeit (falls gesetzt)
  ctx.strokeStyle = 'rgba(241,196,15,0.75)';
  ctx.lineWidth = 2;
  ctx.setLineDash([6,5]);
  if(session.sched_start){
    const xg = xOf(session.sched_start);
    if(xg >= M.l-1 && xg <= M.l+pw+1){
      ctx.beginPath(); ctx.moveTo(xg,M.t); ctx.lineTo(xg,M.t+ph); ctx.stroke();
    }
  }
  if(session.sched_end){
    const xg = xOf(session.sched_end);
    if(xg >= M.l-1 && xg <= M.l+pw+1){
      ctx.beginPath(); ctx.moveTo(xg,M.t); ctx.lineTo(xg,M.t+ph); ctx.stroke();
    }
  }
  ctx.setLineDash([]);
  ctx.lineWidth = 1;

  // Blaue Linien: echter Start und echter Stopp (Position der gelben Linie beim Druck)
  ctx.strokeStyle = 'rgba(52,152,219,0.85)';
  ctx.lineWidth = 2;
  if(session.started_at){
    const xs = xOf(session.started_at);
    if(xs >= M.l && xs <= M.l+pw){ ctx.beginPath(); ctx.moveTo(xs,M.t); ctx.lineTo(xs,M.t+ph); ctx.stroke(); }
  }
  if(session.stopped_at){
    const xe = xOf(session.stopped_at);
    if(xe >= M.l && xe <= M.l+pw){ ctx.beginPath(); ctx.moveTo(xe,M.t); ctx.lineTo(xe,M.t+ph); ctx.stroke(); }
  }
  ctx.lineWidth = 1;

  // Treppenkurven: grün = IN, rot = OUT, grau = undef — nur der sichtbare Bereich
  function curve(getVal, color, fill){
    ctx.strokeStyle = color; ctx.lineWidth = 2.2; ctx.beginPath();
    let pv = getVal(pts[0]);
    for(const p of pts){ if(p.t <= vs) pv = getVal(p); }   // Zustand am linken Rand
    const x0 = xOf(Math.max(vs, pts[0].t));
    ctx.moveTo(x0, yOf(pv));
    for(let i=1;i<pts.length;i++){
      const p = pts[i];
      if(p.t <= vs) continue;
      if(p.t > vs + vlen) break;
      ctx.lineTo(xOf(p.t), yOf(pv));       // horizontal bis zum Event
      ctx.lineTo(xOf(p.t), yOf(getVal(p))); // Sprung
      pv = getVal(p);
    }
    const xe = xOf(Math.min(Math.max(now, vs), vs+vlen));
    ctx.lineTo(xe, yOf(pv));
    ctx.stroke(); ctx.lineWidth = 1;
    /* transparente Fläche unterhalb der Kurve in ihrer jeweiligen Farbe */
    if(fill){
      ctx.lineTo(xe, M.t + ph); ctx.lineTo(x0, M.t + ph); ctx.closePath();
      ctx.fillStyle = fill; ctx.fill();
    }
  }
  curve(p=>p.in, '#2ecc71', 'rgba(46,204,113,0.12)');
  curve(p=>p.out, '#e74c3c', 'rgba(231,76,60,0.12)');
  curve(p=>p.undef, '#8b98a5', 'rgba(139,152,165,0.10)');

  // Fanfare beim Eintritt in die letzten 10% der geplanten Zeit (orange Zone)
  if(started && !stopped && archive === false && !fanfared && elapsed >= planned*0.9){
    fanfared = true; fanfare();
  }

  // Geplante Start-/Endzeit erreicht -> Alarm (drei gleiche Töne), nur live
  if(!archive){
    const nowS = Math.floor(Date.now()/1000);
    if(session.sched_start && !alarmedStart && nowS >= session.sched_start){
      alarmedStart = true; if(nowS - session.sched_start < 120) alarmTones();
    }
    if(session.sched_end && !alarmedEnd && nowS >= session.sched_end){
      alarmedEnd = true; if(nowS - session.sched_end < 120) alarmTones();
    }
  }

  /* Legende UNTERHALB der x-Achse: vergrößerte Farbfelder mit der Zahl der
     Studenten je Zustand; bei genug Platz eine zweite Zeile für die Linien. */
  const lastP = pts[pts.length-1];
  ctx.font='bold 12px system-ui'; ctx.textAlign='left';
  const sqA = H-20, txA = H-9;                    // Farbfelder + Zahlen (unterste Zeile)
  ctx.fillStyle='#2ecc71'; ctx.fillRect(M.l+8,sqA,14,14);
  ctx.fillStyle='#e74c3c'; ctx.fillRect(M.l+118,sqA,14,14);
  ctx.fillStyle='#8b98a5'; ctx.fillRect(M.l+238,sqA,14,14);
  ctx.fillStyle='#e8edf2';
  ctx.fillText('IN · '+lastP.in, M.l+27, txA);
  ctx.fillText('OUT · '+lastP.out, M.l+137, txA);
  ctx.fillText(t('legUndef')+' · '+lastP.undef, M.l+257, txA);
  ctx.font='11px system-ui'; ctx.fillStyle='#8b98a5';
  if(legB){ /* zweite Zeile: gelb gestrichelt = geplante Zeiten, gelb = aktuelle
     Zeit, blau = echter Start/Stopp */
  const sqB = H-42, txB = H-31;
  ctx.lineWidth = 2;
  ctx.strokeStyle = 'rgba(241,196,15,0.8)'; ctx.setLineDash([5,4]);
  ctx.beginPath(); ctx.moveTo(M.l+8,txB-4); ctx.lineTo(M.l+30,txB-4); ctx.stroke();
  ctx.setLineDash([]);
  ctx.fillText(t('legSched'), M.l+34, txB);
  ctx.strokeStyle = '#f1c40f';
  ctx.beginPath(); ctx.moveTo(M.l+160,txB-4); ctx.lineTo(M.l+182,txB-4); ctx.stroke();
  ctx.fillText(t('legNow'), M.l+186, txB);
  ctx.strokeStyle = 'rgba(52,152,219,0.85)';
  ctx.beginPath(); ctx.moveTo(M.l+300,txB-4); ctx.lineTo(M.l+322,txB-4); ctx.stroke();
  ctx.fillText(t('legStart'), M.l+326, txB);
  ctx.lineWidth = 1;
  }
  ctx.fillStyle='#e8edf2'; ctx.font='bold 15px system-ui'; ctx.textAlign='center';
  const rem = Math.max(0, planned - elapsed);
  const over = started && !stopped && elapsed > planned;
  const mid = M.l + pw/2;
  ctx.fillText(!started ? t('chartWait') : (stopped ? t('chartDone') : ''), mid, M.t+18);
  ctx.font='11px system-ui';

  // Große Zeitanzeige zwischen Diagramm und Messages: (verstrichene Zeit) — (übrige Zeit)
  // Verstrichene Zeit wird zur vollen Minute abgerundet, übrige Zeit ist dann exakt
  // (Gesamtzeit - angezeigte verstrichene Zeit): die Summe stimmt immer, und Restzeit
  // 00:00 heißt erst, wenn die geplante Zeit wirklich um ist.
  const bt = document.getElementById('bigtime');
  if(bt){
    const at = document.getElementById('archtime');
    if(archive){
      /* Archiv: Ist/Soll-Zusammenfassung über dem Diagramm, "geplant" je neue Zeile */
      bt.classList.add('hidden');
      if(at){
        at.classList.remove('hidden');
        const durAct = session.started_at
          ? fmt(Math.max(0, (session.stopped_at || archEnd || session.started_at) - session.started_at))
          : t('archNone');
        const line = (lbl, act, plann) =>
          '<span>' + lbl + act + (plann ? '<br><span class="pl">' + t('archPlanned') + plann + t('archParen') + '</span>' : '') + '</span>';
        at.innerHTML =
          line(t('archStart'), session.started_at ? fmtDT(session.started_at) : t('archNone'),
               session.sched_start ? fmtDT(session.sched_start) : null) +
          line(t('archStop'),  session.stopped_at ? fmtDT(session.stopped_at) : t('archNone'),
               session.sched_end ? fmtDT(session.sched_end) : null) +
          line(t('archDur'),   durAct, fmt(planned));
      }
    } else {
      if(at) at.classList.add('hidden');
      bt.classList.remove('hidden');
    const eMin = Math.floor(elapsed/60)*60;            // abgelaufene, volle Minuten
    const remDisp = Math.max(0, planned - eMin);       // passt als Komplement dazu
    if(elapsed > planned){
      // geplante Zeit verbraucht: Überziehung zählt rot blinkend mit Plus nach oben (aufgehend)
      const overMin = Math.ceil((elapsed-planned)/60)*60;
      bt.innerHTML = '<span>'+fmt(eMin)+'</span><span class="bsep">—</span>'
        + '<span class="red blink">+'+fmt(overMin)+'</span>';
    } else if(elapsed >= planned*0.9){
      // letzte 10% der geplanten Zeit: Übrige Zeit gelb
      bt.innerHTML = '<span>'+fmt(eMin)+'</span><span class="bsep">—</span>'
        + '<span class="'+(stopped?'gray':'yellow')+'">'+fmt(remDisp)+'</span>';
    } else {
      bt.innerHTML = '<span>'+fmt(eMin)+'</span><span class="bsep">—</span>'
        + '<span class="'+(stopped?'gray':'')+'">'+fmt(remDisp)+'</span>';
    }
    bt.classList.remove('arch');
    }
  }

  // Statuszeile (nur live, im Archiv steht die Info in der Archivleiste)
  const last = pts[pts.length-1];
  if(archive) updateChatMark();
  const statEl = document.getElementById('stat');
  if(statEl) statEl.textContent =
    (started ? '' : t('statNot')) +
    t('statLive')(last.joined, last.in, last.out, last.undef);
}
function fmt(sec){ sec = Math.max(0, sec|0); // HH:MM
  return String(Math.floor(sec/3600)).padStart(2,'0')+':'+String(Math.floor(sec%3600/60)).padStart(2,'0'); }
setInterval(()=>{ if(session && !archive) render(); }, 1000); // Takt für laufende Zeit
setInterval(()=>{ if(session && !archive && (filterStu || dragStart !== null)) render(); }, 120); // flüssiges Blinken/Band
resumeSession();
</script>
</body>
</html>
<?php }

/* ============================================================ */
function student_view(string $s): void { ?>
<!DOCTYPE html>
<html lang="de">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1">
<title>Lecture Tool ATX</title>
<style>
:root{--green:#2ecc71;--red:#e74c3c}
*{box-sizing:border-box}
body{margin:0;font-family:system-ui,sans-serif;background:#101418;color:#e8edf2;
     display:flex;flex-direction:column;align-items:center;justify-content:center;
     min-height:100vh;padding:16px;gap:18px}
h1{font-size:1rem;color:#8b98a5;margin:0;font-weight:500}
button.state{width:100%;max-width:420px;padding:34px 18px;border-radius:16px;border:none;
  font-size:1.25rem;font-weight:700;cursor:pointer;color:#fff;transition:all .25s}
button.in{background:#145c33;box-shadow:0 0 26px 6px var(--green);animation:glowG 2.2s infinite}
button.out{background:#4a1512;box-shadow:0 0 26px 6px var(--red);animation:glowR 2.2s infinite}
#btnRound{width:190px;height:190px;border-radius:50%;border:3px solid #2a323c;background:#101418;
  color:#e8edf2;font:inherit;font-weight:800;font-size:1.05rem;cursor:pointer;transition:all .25s;padding:10px}
#btnRound.in{border-color:#2ecc71;background:rgba(46,204,113,.16);color:#2ecc71;box-shadow:0 0 26px 6px var(--green)}
#btnRound.out{border-color:#e74c3c;background:rgba(231,76,60,.16);color:#e74c3c;box-shadow:0 0 26px 6px var(--red)}
#btnRound:disabled{opacity:.45;cursor:not-allowed}
button.in.dimmed{background:#183626;box-shadow:0 0 8px 0 rgba(46,204,113,.25);animation:none;opacity:.75}
button.out.dimmed{background:#3a201e;box-shadow:0 0 8px 0 rgba(231,76,60,.25);animation:none;opacity:.75}
@keyframes glowG{0%,100%{box-shadow:0 0 18px 4px var(--green)}50%{box-shadow:0 0 34px 10px var(--green)}}
@keyframes glowR{0%,100%{box-shadow:0 0 18px 4px var(--red)}50%{box-shadow:0 0 34px 10px var(--red)}}
dialog{border:none;border-radius:16px;background:#1a2027;color:#e8edf2;padding:22px;width:min(92vw,420px)}
dialog::backdrop{background:rgba(0,0,0,.6)}
dialog h2{font-size:1.05rem;margin:0 0 14px}
.emojis{display:flex;flex-wrap:wrap;gap:10px;margin:12px 0 16px}
.emojis button{font-size:1.6rem;background:#2c3540;border:none;border-radius:10px;
  padding:8px 10px;cursor:pointer}
.emojis button.sel{background:#2ecc71;outline:2px solid #fff}
.sliderow{display:flex;align-items:center;gap:8px;margin:10px 0 4px}
.sllabel{font-size:.8rem;color:#8b98a5;flex:1}
.slbtn{width:46px;height:36px;font-size:1rem;font-weight:700;background:#2c3540;border:none;
  border-radius:10px;color:#e8edf2;cursor:pointer}
.slwheel{display:flex;flex-direction:column;align-items:center;min-width:2.4em;line-height:1.1}
.sltop,.slbot{color:#8b98a5;font-size:.95rem;opacity:.85}
.slval{font-size:1.25rem;font-weight:700;color:#f1c40f}
.slclear{background:none;border:none;color:#8b98a5;text-decoration:underline;cursor:pointer;
  font:inherit;font-size:.78rem}
textarea{width:100%;min-height:70px;border-radius:10px;border:1px solid #2a323c;
  background:#101418;color:#e8edf2;padding:10px;font:inherit;resize:vertical}
.row{display:flex;gap:10px;margin-top:14px}
.row button{flex:1;padding:12px;border:none;border-radius:10px;font-weight:700;cursor:pointer;font-size:1rem}
.send{background:var(--green);color:#08130b}
.skip{background:#2c3540;color:#8b98a5}
.hint{font-size:.8rem;color:#8b98a5;text-align:center}
#btnLeave{position:fixed;right:14px;bottom:14px;background:none;border:none;color:#8b98a5;
  font:inherit;font-size:.9rem;cursor:pointer;padding:8px 10px;text-decoration:underline}
#btnLeave:hover{color:#e8edf2}
#farewell{position:fixed;inset:0;background:#101418;display:flex;flex-direction:column;
  align-items:center;justify-content:center;gap:14px;z-index:10;text-align:center;padding:20px}
#stateMsg{font-size:1rem;color:#8b98a5;text-align:center}
#stateMsg.hidden{display:none}
#finished{position:fixed;inset:0;background:#101418;display:flex;flex-direction:column;
  align-items:center;justify-content:center;gap:14px;z-index:9;text-align:center;padding:20px;
  font-size:1.2rem}
#finished.hidden{display:none}
#farewell.hidden,#stateMsg.hidden,#finished.hidden{display:none}
#farewell a{color:#2ecc71;cursor:pointer;text-decoration:underline}
#stateMsg{position:static}
button.state.ask{animation:glowG 1.6s infinite}
button.state.out.ask{animation:glowR 1.6s infinite .8s}
button.state:disabled{opacity:.45;cursor:not-allowed;animation:none}
#askhint{color:#f1c40f;font-size:.95rem;text-align:center;margin:0;min-height:1.3em}
#votebox{position:fixed;inset:0;background:rgba(16,20,24,.97);z-index:12;display:flex;
  flex-direction:column;align-items:center;justify-content:center;gap:14px;padding:20px;text-align:center}
#votebox.hidden{display:none}
#votebox h2{margin:0;font-size:1.15rem}
#votedlg-close{background:none;border:none;color:#8b98a5;text-decoration:underline;cursor:pointer;font:inherit}
#keypad{display:grid;grid-template-columns:repeat(3,64px);gap:10px}
#keypad button{font-size:1.4rem;font-weight:700;padding:14px;border:none;border-radius:12px;
  background:#2c3540;color:#e8edf2;cursor:pointer}
#keypad button.sel{background:#7a4a10;color:#ffe3b3;outline:2px solid #f39c12;
  animation:keyGlow 1.6s infinite} /* gewählte Zahl leuchtet mystisch orange */
@keyframes keyGlow{0%,100%{box-shadow:0 0 14px 4px rgba(243,156,18,.55)}50%{box-shadow:0 0 30px 9px rgba(243,156,18,.95)}}
#key0{grid-column:1/4;width:64px;margin:0 auto}
.klabel{font-size:.75rem;color:#8b98a5}
#voteopts{display:flex;flex-direction:column;gap:8px;max-width:420px;width:100%}
#keypad.hidden,#voteopts.hidden,.klabel.hidden{display:none}
#voteopts button{padding:12px 16px;border:none;border-radius:12px;background:#2c3540;
  color:#e8edf2;font:inherit;font-size:.95rem;cursor:pointer}
#voteopts button.sel{background:#7a4a10;color:#ffe3b3;outline:2px solid #f39c12;
  animation:keyGlow 1.6s infinite}
#evalbox{position:fixed;inset:0;background:rgba(16,20,24,.97);z-index:13;display:flex;
  flex-direction:column;align-items:center;justify-content:center;gap:12px;padding:20px;text-align:center}
#evalbox.hidden{display:none}
#evalopts{display:flex;flex-direction:column;gap:8px;max-width:420px;width:100%}
#evalopts button{padding:12px 16px;border:none;border-radius:12px;background:#2c3540;
  color:#e8edf2;font:inherit;font-size:.95rem;cursor:pointer}
#evalopts button.sel{background:#7a4a10;color:#ffe3b3;outline:2px solid #f39c12;font-weight:700}
#evalcmt{width:100%;max-width:420px;min-height:70px;border-radius:10px;border:1px solid #2a323c;
  background:#101418;color:#e8edf2;padding:10px;font:inherit;resize:vertical}
#evalcmt.hidden{display:none}
#langsw{position:fixed;left:14px;bottom:14px;display:flex;gap:6px;z-index:11}
#langsw button{background:none;border:1px solid #2a323c;color:#8b98a5;font:inherit;
  font-size:.75rem;cursor:pointer;padding:4px 9px;border-radius:8px}
#langsw button.on{background:#2ecc71;color:#08130b;border-color:#2ecc71;font-weight:700}
body.lang-de .en{display:none}
body.lang-en .de{display:none}
details.legal{width:100%;max-width:420px;font-size:.72rem;color:#8b98a5}
details.legal summary{cursor:pointer;text-decoration:underline;padding:2px 0}
details.legal .legal-body{line-height:1.5;margin-top:6px}
details.legal p,details.legal li{margin:4px 0;text-align:left}
details.legal ul{margin:4px 0;padding-left:18px}
details.legal a{color:#2ecc71}
</style>
</head>
<body>
<h1>🎓 Lecture Tool ATX</h1>
<p style="font-size:.8rem;color:#8b98a5;margin:0 0 8px"><span class="de">ATX steht für „Attention Tracker“</span><span class="en">ATX stands for “Attention Tracker”</span></p>
<div id="langsw">
  <button id="btnLangDe" onclick="setLang('de')">🇩🇪 DE</button>
  <button id="btnLangEn" onclick="setLang('en')">🇬🇧 EN</button>
</div>
<div id="stateMsg" class="hidden"><b><span class="de">⏳ Die Vorlesung hat noch nicht begonnen</span><span class="en">⏳ Lecture not started yet</span></b></div>
<div id="finished" class="hidden"><div style="font-size:1.6rem">🏁</div><div><b><span class="de">Die Vorlesung ist beendet</span><span class="en">Lecture is finished</span></b></div><div style="font-size:.9rem;color:#8b98a5"><span class="de">Danke für deine Aufmerksamkeit!</span><span class="en">Thanks for your attention!</span></div></div>
<div id="evalexp" class="hidden" style="margin-top:10px;font-size:.85rem;color:#8b98a5"><span class="de">⏳ Die Bewertungsfrist von 24 Stunden ist abgelaufen — eine Bewertung ist nicht mehr möglich.</span><span class="en">⏳ The 24-hour evaluation deadline has passed — the evaluation is no longer available.</span></div>
<button class="state in dimmed" id="btnIn"><span class="de">✅ Du hast meine Aufmerksamkeit</span><span class="en">✅ You have my attention</span></button>
<button class="state out dimmed" id="btnOut"><span class="de">😴 Sorry, ich bin abgeschaltet</span><span class="en">😴 Sorry, I disengaged</span></button>
<button id="btnRound" style="display:none"></button>
<p class="hint" id="askhint" style="display:none"></p>
<p class="hint"><span class="de">Dein Status wird anonym übermittelt.</span><span class="en">Your status is transmitted anonymously.</span></p>
<button id="btnLeave" onclick="leave()"><span class="de">Verlassen &amp; abmelden</span><span class="en">Leave &amp; logout</span></button>

<div id="farewell" class="hidden">
  <div style="font-size:1.3rem">👋</div>
  <div><span class="de">Du hast die Vorlesung verlassen.<br>Danke für deine Teilnahme!</span><span class="en">You have left the lecture.<br>Thanks for your participation!</span></div>
  <div style="font-size:.85rem;color:#8b98a5;max-width:420px"><span class="de">📋 Hast du die Bewertung noch nicht ausgefüllt? Du hast bis zu 24 Stunden nach Vorlesungende Zeit dafür — öffne den Link einfach erneut.</span><span class="en">📋 Haven't filled in the evaluation yet? You have up to 24 hours after the lecture ends — simply open the link again.</span></div>
  <a onclick="location.reload()"><span class="de">Wieder beitreten</span><span class="en">Rejoin</span></a>
</div>

<div id="votebox" class="hidden">
  <h2 id="votetitle"><span class="de">🗳 Abstimmung</span><span class="en">🗳 Vote</span></h2>
  <div style="color:#8b98a5;font-size:.85rem" id="votedlg-info"></div>
  <div id="voteopts"></div>
  <div id="keypad"></div>
  <div class="klabel" id="votefreehint"><span class="de">Tippen loggt deine Wahl · „Absenden“ gibt sie sofort ab, sonst zählt sie automatisch am Ende der Zeit · 0 = Enthaltung · letzte Wahl zählt</span><span class="en">Tapping logs your choice · “Submit” casts it immediately, otherwise it counts automatically when time runs out · 0 = abstain · last choice counts</span></div>
  <div class="btn-row" style="gap:10px">
    <button id="btnVoteSend" class="send" style="padding:12px 18px;border:none;border-radius:10px;font-weight:700" onclick="confirmVote()"><span class="de">Absenden</span><span class="en">Send now</span></button>
    <button id="votedlg-close" onclick="hideVote()"><span class="de">Ausblenden (Änderung bis Ablauf möglich)</span><span class="en">Hide (changes allowed until it ends)</span></button>
  </div>
</div>

<div id="evalbox" class="hidden">
  <h2><span class="de">📝 Bewertung der Vorlesung</span><span class="en">📝 Lecture evaluation</span></h2>
  <div style="color:#f1c40f;font-weight:700" id="evalq-no"></div>
  <div style="font-size:.75rem;color:#8b98a5;margin-bottom:6px" id="evaldl"></div>
  <div style="max-width:420px;line-height:1.4" id="evalq-text"></div>
  <div class="evalopts" id="evalopts"></div>
  <textarea id="evalcmt" class="hidden" placeholder=""></textarea>
  <button class="send" id="evalsend" style="margin-top:10px"><span class="de">Absenden</span><span class="en">Send</span></button>
</div>

<details class="legal">
  <summary><span class="de">Impressum &amp; Datenschutz</span><span class="en">Legal notice &amp; privacy</span></summary>
  <div class="legal-body">
    <div class="de">
      <p><b>Impressum (§ 5 DDG):</b> Timo Damm, Butten 2, 24107 Kiel, Deutschland · E-Mail: <a href="mailto:info@pixcaelium.de">info@pixcaelium.de</a></p>
      <p><b>Datenschutz:</b> Keine Cookies, kein Tracking. Beim Öffnen dieser Seite erzeugt dein Browser ein rein zufälliges, anonymes Token (lokal gespeichert); personenbezogene Daten (Name, E-Mail, Matrikelnummer) werden nicht erhoben, IP-Adressen nicht protokolliert. Deine Eingaben (IN/OUT, Emoji, Nachricht, Abstimmung, Bewertung) werden verschlüsselt (AES-256-GCM) und ohne Personenbezug auf dem Server der Veranstaltung gespeichert, bis der Dozent sie löscht; die Abschlussbewertung kannst du bis 24 Stunden nach Veranstaltungsende nachreichen, auch wenn du die Veranstaltung bereits verlassen hast. Bitte gib in Nachrichten und Kommentaren keine personenbezogenen Angaben ein. Keine Weitergabe an Dritte. Deine Rechte nach Art. 15–20 DSGVO (Auskunft, Berichtigung, Löschung, Einschränkung, Datenübertragbarkeit) kannst du per E-Mail geltend machen; Beschwerden sind an eine Datenschutz-Aufsichtsbehörde (Art. 77) möglich.</p>
      <p><b>Credits:</b> Die Grundidee zum Attention Tracker stammt von Franziska Lohrengel und Jan-Bernd Hövener — herzlichen Dank dafür.</p>
    </div>
    <div class="en">
      <p><b>Legal notice (§ 5 DDG):</b> Timo Damm, Butten 2, 24107 Kiel, Germany · Email: <a href="mailto:info@pixcaelium.de">info@pixcaelium.de</a></p>
      <p><b>Privacy:</b> No cookies, no tracking. When you open this page, your browser generates a purely random, anonymous token (stored locally); no personal data (name, email, matriculation number) is collected and IP addresses are not logged. Your input (IN/OUT, emoji, message, vote, evaluation) is stored encrypted (AES-256-GCM) without any personal reference on the event's server until the lecturer deletes it; you can submit the final evaluation up to 24 hours after the event has ended, even if you have already left it. Please do not enter personal details in messages or comments. No sharing with third parties. You may assert your rights under Art. 15–20 GDPR (access, rectification, erasure, restriction, data portability) by email; complaints may be lodged with a supervisory data protection authority (Art. 77).</p>
      <p><b>Credits:</b> The original idea for the attention tracker is credited to Franziska Lohrengel and Jan-Bernd Hövener — many thanks.</p>
    </div>
  </div>
</details>

<dialog id="dlgOut">
  <h2><span class="de">🤔 Wo habe ich dich verloren?</span><span class="en">🤔 Where did I lose you?</span></h2>
  <div class="emojis" id="emoOut">
    <button>😴</button><button>🐢</button><button>🤯</button><button>📉</button><button>💫</button><button>📱</button><button>❓</button>
  </div>
  <div class="sliderow">
    <span class="sllabel"><span class="de">Folie (optional)</span><span class="en">Slide (optional)</span></span>
    <button type="button" class="slbtn" onclick="slideUp()">▲</button>
    <div class="slwheel">
      <span class="sltop">&nbsp;</span>
      <span class="slval">–</span>
      <span class="slbot">&nbsp;</span>
    </div>
    <button type="button" class="slbtn" onclick="slideDown()">▼</button>
    <button type="button" class="slclear" onclick="slideClear()"><span class="de">leer</span><span class="en">clear</span></button>
  </div>
  <textarea id="msgOut" data-ph="msgOut"></textarea>
  <div class="row"><button class="skip" onclick="closeDlg()"><span class="de">Abbrechen</span><span class="en">Cancel</span></button><button class="send" onclick="send('out')"><span class="de">Absenden</span><span class="en">Send</span></button></div>
</dialog>

<dialog id="dlgIn">
  <h2><span class="de">💡 Ich bin wieder zurück? Erzähl davon</span><span class="en">💡 I got you back? Tell me about it</span></h2>
  <div class="emojis" id="emoIn">
    <button>💡</button><button>😊</button><button>🚀</button><button>✅</button><button>🤩</button><button>🔥</button><button>👍</button>
  </div>
  <div class="sliderow">
    <span class="sllabel"><span class="de">Folie (optional)</span><span class="en">Slide (optional)</span></span>
    <button type="button" class="slbtn" onclick="slideUp()">▲</button>
    <div class="slwheel">
      <span class="sltop">&nbsp;</span>
      <span class="slval">–</span>
      <span class="slbot">&nbsp;</span>
    </div>
    <button type="button" class="slbtn" onclick="slideDown()">▼</button>
    <button type="button" class="slclear" onclick="slideClear()"><span class="de">leer</span><span class="en">clear</span></button>
  </div>
  <textarea id="msgIn" data-ph="msgIn"></textarea>
  <div class="row"><button class="skip" onclick="closeDlg()"><span class="de">Abbrechen</span><span class="en">Cancel</span></button><button class="send" onclick="send('in')"><span class="de">Absenden</span><span class="en">Send</span></button></div>
</dialog>

<script>
const SID = <?= json_encode($s) ?>;
/* ---------------- Sprachumschaltung DE/EN (Standard: Browsersprache) ---------------- */
let LANG = localStorage.getItem('att_lang') ||
  ((navigator.language||'').toLowerCase().startsWith('de') ? 'de' : 'en');
const S_I18N = {
  de: {
    notFound: 'Session nicht gefunden — bitte den QR-Code erneut scannen.',
    leaveConfirm: 'Du verlässt damit das Lecture Tool ATX und schließt deine Session endgültig. Deine Teilnahme an dieser Vorlesung wird beendet. Fortfahren?',
    err: 'Fehler'
  },
  en: {
    notFound: 'Session not found — please scan the QR code again.',
    leaveConfirm: 'You are leaving the Lecture Tool ATX and closing your session permanently. Your participation in this lecture will end. Continue?',
    err: 'Error'
  }
};
const S_PH = {
  msgOut: { de: 'Kurze Nachricht an den Dozenten (optional) …', en: 'Short message to the lecturer (optional) …' },
  msgIn:  { de: 'Was hat dich zurückgebracht? (optional) …',   en: 'What brought you back? (optional) …' }
};
function sT(k){ return (S_I18N[LANG] && S_I18N[LANG][k]) || S_I18N.de[k] || k; }
function setLang(l){
  LANG = l; localStorage.setItem('att_lang', l);
  document.body.classList.remove('lang-de','lang-en'); document.body.classList.add('lang-'+l);
  document.documentElement.lang = l;
  document.getElementById('btnLangDe').classList.toggle('on', l==='de');
  document.getElementById('btnLangEn').classList.toggle('on', l==='en');
  document.querySelectorAll('textarea[data-ph]').forEach(el => { el.placeholder = S_PH[el.dataset.ph][LANG]; });
}
setLang(LANG);
let token = localStorage.getItem('att_tok_' + SID);
if(!token){
  token = 't' + Math.random().toString(36).slice(2,12) + Date.now().toString(36);
  localStorage.setItem('att_tok_' + SID, token);
}
let myState = 'in';   // jeder Student startet IN (kann per Session-Option "undef" sein)
let pickedEmojis = [], pendingState = null, hasLeft = false;
/* Neuentscheidung & Abstimmung: Server-Zeitversatz, Fristen, Status */
let serverOff = 0, decideUntil = 0, voteUntil = 0, myVoteRound = -1, myVoteVal = null, voteConfirmed = false, voteSent = false, askMode = '';
const askHint = () => document.getElementById('askhint');
function nowS(){ return Math.floor(Date.now()/1000 + serverOff); } // Serverzeit lokal
/* kurzer Chirp (gleiche Tonhöhe) für die Countdown-Sekunden */
function chirp(){
  try{
    const AC = window.AudioContext || window.webkitAudioContext;
    chirp.ac = chirp.ac || new AC();
    const ac = chirp.ac, o = ac.createOscillator(), g = ac.createGain();
    o.type = 'sine'; o.frequency.value = 880;
    g.gain.setValueAtTime(0.25, ac.currentTime);
    g.gain.exponentialRampToValueAtTime(0.001, ac.currentTime + 0.09);
    o.connect(g); g.connect(ac.destination);
    o.start(); o.stop(ac.currentTime + 0.09);
  }catch(e){}
}

// Registrierung beim Dozenten direkt beim Öffnen (strikt anonym, idempotent)
fetch(location.pathname + '?s=' + SID, {
  method:'POST', headers:{'Content-Type':'application/json'},
  body: JSON.stringify({action:'join', s:SID, token, lang:LANG})
}).then(r=>r.json()).then(j=>{
  if(!j.ok && j.error === 'session not found'){
    document.body.innerHTML = '<p class="hint">' + sT('notFound') + '</p>';
  }
}).catch(()=>{});

const btnIn = document.getElementById('btnIn');
const btnOut = document.getElementById('btnOut');
const btnRound = document.getElementById('btnRound');
let stuView = 'classic';        // 'round' = runder Knopf (neuer Standard bei Neuanlage), 'classic' = bisherige Ansicht
let allowMsg = false;           // Studenten-Nachrichten erlaubt?
function applyStuViewUI(h){
  if(h === undefined) h = !document.getElementById('finished').classList.contains('hidden');
  const round = stuView === 'round', show = !h;
  btnIn.style.display  = (show && !round) ? '' : 'none';
  btnOut.style.display = (show && !round) ? '' : 'none';
  btnRound.style.display = (show && round) ? '' : 'none';
  document.getElementById('msgIn').style.display  = allowMsg ? '' : 'none';
  document.getElementById('msgOut').style.display = allowMsg ? '' : 'none';
}

/* Vorlesungs-Status verfolgen: Start/Stopp beim Dozenten */
let lecState = 'waiting';
let votePack = 0;                 // aktives Optionspaket (0 = freie Ziffernwahl)
let evalQs = [];                  // Bewertungsfragen des Dozenten
let evalIdx = -1, evalPick = null, evalRunning = false;
let evalDeadline = 0;             // Bewertungsfrist: 24 h nach Vorlesungsende
const EVAL_HOURS = 24;
function applyLecState(d){
  const st = d.stopped_at ? 'stopped' : (d.started_at ? 'running' : 'waiting');
  votePack = +(d.vote_pack || 0);
  evalQs = d.eval_qs || [];
  evalDeadline = d.stopped_at ? ((+d.stopped_at) + EVAL_HOURS*3600) : 0;
  stuView = d.stuview || 'classic';
  allowMsg = !!d.allow_msg;
  applyStuViewUI();
  paint();
  if(st === lecState) return;
  lecState = st;
  const msg = document.getElementById('stateMsg'), fin = document.getElementById('finished');
  if(st === 'waiting'){
    msg.classList.remove('hidden'); fin.classList.add('hidden'); hideMain(false);
  } else if(st === 'running'){
    msg.classList.add('hidden'); fin.classList.add('hidden'); hideMain(false);
  } else {
    fin.classList.remove('hidden'); hideMain(true);
    maybeStartEval();
  }
}
function hideMain(h){ applyStuViewUI(h); }
let firedBeeps = {};   // gespielte Chirp-Marken je Entscheidungsminute
let voteOpenShown = false; // Tastatur pro Abstimmungsrunde neu aufbauen
async function pollState(){
  try{
    const d = await fetch(location.pathname + '?api=snapshot&s=' + SID).then(r=>r.json());
    if(!d || !d.id){ return; }
    serverOff = (d.now || Math.floor(Date.now()/1000)) - Math.floor(Date.now()/1000);
    curSlide = consensusSlide(d);   // Mehrheitsfolie für das Drehrad
    /* neue Entscheidungs-/Abstimmungsrunde erkennen: Tastatur + Chirps zurücksetzen */
    if(d.decide_until && d.decide_until !== decideUntil) firedBeeps = {};
    const voteNew = d.vote_until && d.vote_until !== voteUntil;
    decideUntil = d.decide_until || 0;
    voteUntil = d.vote_until || 0;
    askMode = d.ask_mode || '';   /* 'ondemand' = IN/OUT nur während einer Abfrage */
    if(voteNew){ voteOpenShown = false; myVoteVal = null; voteConfirmed = false; voteSent = false; }
    /* autoritativer Zustand vom Server (Start-Option, undef nach Fristablauf) */
    const me = (d.students||{})[token];
    if(me && me.st){ if(me.st !== myState){ myState = me.st; paint(); } }
    if(me && me.vote !== undefined && me.vote !== null) myVoteVal = me.vote;
    applyLecState(d);
    updateAsk(); updateVote(d);
  }catch(e){}
}
pollState();
setInterval(pollState, 4000);

/* Countdown-Ticker für Neuentscheidung (Chirps) und Anzeige der Frist */
setInterval(() => {
  if(decideUntil){
    const rem = decideUntil - nowS();
    if(rem > 0){
      const elapsed = 60 - rem;
      /* je einmal: Start, nach 30 s, nach 45 s, dann jede Sekunde von 51 s bis 60 s */
      const marks = [0, 30, 45];
      for(const m of marks) if(elapsed >= m && !firedBeeps['e'+m]){ firedBeeps['e'+m] = 1; chirp(); }
      if(elapsed >= 50 && !firedBeeps['s'+Math.floor(elapsed)]){ firedBeeps['s'+Math.floor(elapsed)] = 1; chirp(); }
    }
  }
  updateAsk(); // auch Sperre/Zwangshinweis im On-demand-Modus aktuell halten
  /* Bewertungsfrist: über den Fragen laufend herunterzählen */
  if(evalDeadline && !document.getElementById('evalbox').classList.contains('hidden')){
    const dl = document.getElementById('evaldl');
    if(dl) dl.textContent = evalRemText();
  }
}, 250);

function updateAsk(){
  const rem = decideUntil ? Math.max(0, decideUntil - nowS()) : 0;
  const deciding = decideUntil && rem > 0;
  /* On-demand-Modus: IN/OUT ist nur während einer laufenden Abfrage möglich */
  const locked = askMode === 'ondemand' && !deciding;
  btnIn.disabled = btnOut.disabled = locked;
  if(locked){
    btnIn.classList.remove('ask');
    btnOut.classList.remove('ask');
    const h = askHint();
    h.style.display = '';
    h.textContent = LANG==='de'
      ? '🔒 Der Dozent fragt gezielt ab — IN/OUT ist nur während einer Abfrage möglich.'
      : '🔒 The lecturer polls on demand — IN/OUT is only possible during a poll.';
    return;
  }
  const ask = myState === 'undef' || deciding;
  btnIn.classList.toggle('ask', ask);
  btnOut.classList.toggle('ask', ask);
  const h = askHint();
  if(ask){
    h.style.display = '';
    h.textContent = deciding
      ? (LANG==='de' ? 'Bitte neu entscheiden — noch '+Math.ceil(rem)+' s!' : 'Please re-decide — '+Math.ceil(rem)+' s left!')
      : (LANG==='de' ? 'Bitte entscheide dich: IN oder OUT!' : 'Please decide: IN or OUT!');
  } else h.style.display = 'none';
}

/* ---------- Abstimmung: freie Ziffernwahl 1–9/0 oder Optionspaket ---------- */
function buildKeypad(){
  const kp = document.getElementById('keypad');
  kp.innerHTML = '';
  for(let i=1;i<=9;i++) kp.appendChild(keyBtn(i));
  const z = keyBtn(0); z.id = 'key0';
  kp.appendChild(z);
}
function keyBtn(v){
  const b = document.createElement('button');
  b.textContent = String(v);
  b.onclick = () => selectVote(v);
  return b;
}
function selectVote(v){ myVoteVal = v; markKey(v); } // nur loggen, senden ist die Entscheidung des Studenten
async function castVote(v, confirm){
  try{
    const r = await fetch(location.pathname + '?s=' + SID, {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({action:'cast', s:SID, token, val:v, confirm: !!confirm, lang:LANG})
    }).then(r=>r.json());
    if(r && r.ok) markKey(v);
  }catch(e){} // offline-tolerant
}
/* Direktes Absenden: Stimme ist erfasst, der Student muss nicht auf das
   Zeitende oder den Abschluss durch den Dozenten warten. */
async function confirmVote(){
  if(myVoteVal === null){
    alert(LANG==='de' ? 'Bitte wähle zuerst eine Option.' : 'Please choose an option first.');
    return;
  }
  voteConfirmed = true;
  await castVote(myVoteVal, true);
  document.getElementById('votebox').classList.add('hidden');
  const h = askHint();
  h.style.display = '';
  h.textContent = LANG==='de' ? '✓ Deine Stimme ist erfasst.' : '✓ Your vote has been recorded.';
  setTimeout(() => { if(!voteUntil || voteUntil - nowS() <= 0) h.style.display = 'none'; }, 4000);
}
/* Zeit abgelaufen ohne Absenden: die geloggte Wahl zählt automatisch */
async function autoCastOnEnd(){
  if(voteConfirmed || myVoteVal === null || voteSent) return;
  voteSent = true;
  await castVote(myVoteVal, false);
  myVoteVal = null;
}
function markKey(v){
  document.querySelectorAll('#keypad button').forEach(b =>
    b.classList.toggle('sel', b.textContent === String(v)));
  document.querySelectorAll('#voteopts button').forEach(b =>
    b.classList.toggle('sel', b.dataset.v === String(v)));
}
function updateVote(d){
  const box = document.getElementById('votebox');
  const info = document.getElementById('votedlg-info');
  /* abgeschlossene Studenten (direkt gesendet oder abgegeben) sehen die Abstimmung nicht mehr */
  const me = (d.students || {})[token];
  const done = voteConfirmed || (me && me.vote_done && me.vote_done === (d.vote_no || 0));
  const active = voteUntil && (voteUntil - nowS()) > 0 && !done;
  if(active){
    if(!voteOpenShown){
      /* pro Runde neu aufbauen: Optionspaket oder freie Zifferntastatur */
      const kp = document.getElementById('keypad');
      const vo = document.getElementById('voteopts');
      const fh = document.getElementById('votefreehint');
      const title = document.getElementById('votetitle');
      const packObj = votePack > 0 ? (d.vote_packs || [])[votePack - 1] : null;
      if(packObj){
        kp.classList.add('hidden'); fh.classList.add('hidden'); vo.classList.remove('hidden');
        title.textContent = '🗳 ' + packObj.title;
        vo.innerHTML = '';
        (packObj.opts || []).forEach((o, i) => {
          const b = document.createElement('button');
          b.dataset.v = String(i + 1);
          b.textContent = o;
          b.onclick = () => selectVote(i + 1);
          vo.appendChild(b);
        });
      } else {
        kp.classList.remove('hidden'); fh.classList.remove('hidden'); vo.classList.add('hidden');
        title.textContent = LANG === 'de' ? '🗳 Abstimmung' : '🗳 Vote';
        buildKeypad();
      }
      voteOpenShown = true;
    }
    box.classList.remove('hidden');
    const rem = Math.max(0, voteUntil - nowS());
    info.textContent = (LANG==='de' ? 'Noch ' + Math.ceil(rem) + ' s' : Math.ceil(rem) + ' s left');
    if(myVoteVal !== null) markKey(myVoteVal);
    /* kurz vor Ablauf die nur geloggte Wahl zuverlässig abgeben (bevor der
       Server das Fenster schließt), falls der Student nicht selbst sendet */
    if(rem > 0 && rem <= 1.2) autoCastOnEnd();
  } else {
    /* Zeit abgelaufen oder Abstimmung beendet: die nur geloggte Wahl zählt automatisch */
    autoCastOnEnd();
    box.classList.add('hidden');
  }
}
function hideVote(){ document.getElementById('votebox').classList.add('hidden'); }

/* ---------- Bewertung: Fragen erscheinen erst nach dem Stopp, ---------- */
/* eine nach der anderen, mit Zähler "Frage 1/5" */
function maybeStartEval(){
  if(evalRunning || !evalQs.length) return;
  if(localStorage.getItem('att_eval_done_' + SID)) return;
  /* Bewertungsfrist abgelaufen: Bewertung ist nicht mehr möglich */
  if(evalDeadline && nowS() > evalDeadline){
    const exp = document.getElementById('evalexp');
    if(exp) exp.classList.remove('hidden');
    return;
  }
  evalRunning = true; evalIdx = 0; renderEval();
}
function evalRemText(){
  const rem = Math.max(0, evalDeadline - nowS());
  const h = Math.floor(rem/3600), m = Math.floor((rem%3600)/60);
  return LANG==='de' ? '⏳ Bewertungsfrist: noch '+h+' h '+m+' min' : '⏳ Evaluation deadline: '+h+' h '+m+' min left';
}
function renderEval(){
  const box = document.getElementById('evalbox');
  if(evalIdx >= evalQs.length){
    localStorage.setItem('att_eval_done_' + SID, '1');
    evalRunning = false;
    box.classList.add('hidden');
    return;
  }
  const q = evalQs[evalIdx];
  box.classList.remove('hidden');
  document.getElementById('evaldl').textContent = evalDeadline ? evalRemText() : '';
  document.getElementById('evalq-no').textContent =
    (LANG==='de' ? 'Frage ' : 'Question ') + (evalIdx + 1) + '/' + evalQs.length;
  document.getElementById('evalq-text').textContent = q.q;
  evalPick = null;
  const opts = document.getElementById('evalopts');
  opts.innerHTML = '';
  (q.opts || []).forEach(o => {
    const b = document.createElement('button');
    b.textContent = o;
    b.onclick = () => { evalPick = o;
      opts.querySelectorAll('button').forEach(x => x.classList.remove('sel'));
      b.classList.add('sel'); };
    opts.appendChild(b);
  });
  const cmt = document.getElementById('evalcmt');
  if(q.cmt){
    cmt.classList.remove('hidden'); cmt.value = '';
    /* reine Kommentarfrage („|c“ ohne Optionen): Freitext ist die Antwort */
    cmt.placeholder = (q.opts || []).length
      ? (LANG==='de' ? 'Optionaler Kommentar …' : 'Optional comment …')
      : (LANG==='de' ? 'Deine Antwort …' : 'Your answer …');
  } else { cmt.classList.add('hidden'); cmt.value = ''; }
}
async function sendEvalAnswer(){
  const q = evalQs[evalIdx];
  const cmtVal = q.cmt ? document.getElementById('evalcmt').value.trim() : '';
  if((q.opts || []).length){
    if(evalPick === null){
      alert(LANG==='de' ? 'Bitte wähle eine Antwort.' : 'Please choose an answer.');
      return;
    }
  } else {
    /* Kommentarfrage: Freitext ist erforderlich */
    if(!cmtVal){
      alert(LANG==='de' ? 'Bitte schreibe eine Antwort in das Textfeld.' : 'Please write an answer in the text field.');
      return;
    }
  }
  try{
    await fetch(location.pathname + '?s=' + SID, {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({action:'eval', s:SID, token, q:evalIdx, a:evalPick,
        c:q.cmt ? document.getElementById('evalcmt').value.trim() : '', lang:LANG})
    });
  }catch(e){} // offline-tolerant: nächste Frage trotzdem zeigen
  evalIdx++; renderEval();
}
document.getElementById('evalsend').onclick = sendEvalAnswer;

function paint(){
  btnIn.className  = 'state in'  + (myState==='in'  ? '' : ' dimmed');
  btnOut.className = 'state out' + (myState==='out' ? '' : ' dimmed');
  if(stuView === 'round'){
    btnRound.classList.remove('in','out');
    btnRound.classList.add(myState === 'out' ? 'out' : 'in');
    btnRound.disabled = pollLocked() || hasLeft;
    btnRound.innerHTML = myState === 'out'
      ? '<span class="de">😴 OUT — tippen für IN</span><span class="en">😴 OUT — tap for IN</span>'
      : '<span class="de">✅ IN — tippen für OUT</span><span class="en">✅ IN — tap for OUT</span>';
  }
  updateAsk();
}
function wireEmoji(containerId){
  document.querySelectorAll('#'+containerId+' button').forEach(b=>{
    b.onclick = () => {
      const i = pickedEmojis.indexOf(b.textContent);
      if(i >= 0){ pickedEmojis.splice(i,1); b.classList.remove('sel'); } // abwählen
      else { pickedEmojis.push(b.textContent); b.classList.add('sel'); }  // mehrfach auswählen
    };
  });
}
wireEmoji('emoOut'); wireEmoji('emoIn');

/* Folien-Drehrad: die Mitte zeigt die Auswahl (– = undefiniert, wird nicht
   mitgeschickt), direkt darunter steht die Startfolie (eigene letzte gesendete,
   sonst die Mehrheitsfolie aller Studenten), direkt darueber die naechste.
   Drehen verschiebt das Rad um je eine Folie. */
let slideK = 0;        // 0 = undefiniert; >0 = Folie start+K; <0 = Folie start+K+1
let slideStart = 1;    // Anker: untere der beiden Zahlen beim Start
let lastSlide = +(localStorage.getItem('att_slide_' + SID) || 0);
let curSlide = 0;      // Mehrheitsfolie der Studenten (aus den letzten 10 Minuten)
function slideOf(k){ return k === 0 ? null : slideStart + k + (k < 0 ? 1 : 0); }
function lab(k){ const v = slideOf(k); return (v === null) ? '–' : (v >= 1 ? String(v) : ''); }
function paintSlide(){
  document.querySelectorAll('.sltop').forEach(el => el.textContent = lab(slideK + 1));
  document.querySelectorAll('.slval').forEach(el => el.textContent = lab(slideK));
  document.querySelectorAll('.slbot').forEach(el => el.textContent = lab(slideK - 1));
}
function slideUp(){
  const v = slideOf(slideK + 1);
  if(v !== null && v <= 999) slideK++;
  paintSlide();
}
function slideDown(){
  const v = slideOf(slideK - 1);
  if(v === null || v >= 1) slideK--;
  paintSlide();
}
function slideClear(){ slideK = 0; paintSlide(); }
/* Mehrheitsfolie: haeufigste Folienangabe der letzten 10 Minuten,
   bei Gleichstand die hoehere, als Fallback die letzte genannte */
function consensusSlide(d){
  const cutoff = (d.now || Math.floor(Date.now()/1000)) - 600;
  const cnt = {}; let last = 0;
  for(const e of (d.events || [])){
    if(e.slide > 0){
      if(e.t >= cutoff) cnt[e.slide] = (cnt[e.slide] || 0) + 1;
      last = e.slide;
    }
  }
  let best = 0, bestN = 0;
  for(const k in cnt){ if(cnt[k] > bestN || (cnt[k] === bestN && +k > best)){ best = +k; bestN = cnt[k]; } }
  return best || last;
}
function openSlide(){ slideK = 0; slideStart = Math.max(1, lastSlide || curSlide || 1); paintSlide(); }
paintSlide();

function closeDlg(){
  document.getElementById('dlgOut').close();
  document.getElementById('dlgIn').close();
  if(pendingState==='out' && myState==='in'){ /* abgebrochen */ }
  pendingState = null; pickedEmojis = [];
}

/* On-demand-Modus: außerhalb einer laufenden Abfrage ist IN/OUT gesperrt */
function pollLocked(){ return askMode === 'ondemand' && !(decideUntil && decideUntil - nowS() > 0); }
btnOut.onclick = () => { if(myState==='out'||hasLeft||pollLocked()) return; pendingState='out'; pickedEmojis=[]; openSlide(); document.getElementById('msgOut').value=''; document.getElementById('dlgOut').showModal(); };
btnIn.onclick  = () => { if(myState==='in'||hasLeft||pollLocked())  return; pendingState='in';  pickedEmojis=[]; openSlide(); document.getElementById('msgIn').value='';  document.getElementById('dlgIn').showModal(); };
btnRound.onclick = () => {
  if(hasLeft || pollLocked()) return;
  const to = myState === 'out' ? 'in' : 'out';
  document.getElementById(to === 'out' ? 'msgOut' : 'msgIn').value = '';
  pickedEmojis = []; slideK = 0;
  send(to);
};

async function leave(){
  if(!confirm(sT('leaveConfirm'))) return;
  hasLeft = true;
  try{
    await fetch(location.pathname + '?s=' + SID, {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({action:'leave', s:SID, token, lang:LANG})
    });
  }catch(e){}
  /* Token nur während der laufenden Vorlesung verwerfen (Reload = neuer Student).
     Nach dem Stopp bleibt er erhalten, damit die Bewertung (24-h-Frist)
     auch nach dem Verlassen noch möglich ist — der Dozent-Server prüft die Frist. */
  if(lecState !== 'stopped') localStorage.removeItem('att_tok_' + SID);
  document.getElementById('farewell').classList.remove('hidden');
}

async function send(state){
  const msg = document.getElementById(state==='out'?'msgOut':'msgIn').value.trim();
  const sl = slideOf(slideK);
  try{
    const r = await fetch(location.pathname + '?s=' + SID, {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({action:'toggle', s:SID, token, state, msg, emoji:pickedEmojis.join(''), slide:sl, lang:LANG})
    });
    const j = await r.json();
    if(!j.ok){
      if(j.error === 'finished'){ pollState(); return; }
      alert(j.error || sT('err')); return;
    }
    myState = state;
    if(sl){ lastSlide = sl; localStorage.setItem('att_slide_' + SID, sl); }
  }catch(e){ myState = state; if(sl){ lastSlide = sl; localStorage.setItem('att_slide_' + SID, sl); } paint(); return; } // offline-tolerant
  paint(); closeDlg();
}
paint();
</script>
</body>
</html>
<?php }
