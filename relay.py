"""
WebSocket relay — iki tərəfi `(token, channel)` açarı ilə cütləşdirir və
aralarında kor (blind) bayt ötürməsi aparır.

Qəsdən `auth_server.py`-dəki DB/token-doğrulama məntiqindən AYRI saxlanılıb
ki, HTTP-dən/DB-dən keçmədən, sadəcə iki obyekt ilə birbaşa test edilə
bilsin (bax server/README_SERVER_AZ.md-də test ardıcıllığı).

Qərar: bağlantı kəsiləndə (hər hansı tərəfdən) bütün cüt DAĞILIR — davam
etdirmə (resume) YOXDUR. Yenidən qoşulmaq tamamilə YENİ handshake tələb
edir. Bu, FILE kanalı üçün sıra-nömrələmə və INPUT üçün "split-brain"
riskindən qaçır, həm də köhnə token-in sonsuza qədər "qoşalaşdırıla bilən"
qalmasının qarşısını alır.
"""

from __future__ import annotations

import threading
import time

SLOT_TIMEOUT = 60.0       # bir tərəf tək qalıbsa bu qədər saniyədən sonra ləğv olunur
SWEEP_INTERVAL = 10.0


class _Slot:
    __slots__ = ("conn", "event", "peer", "created", "pump_done")

    def __init__(self, conn):
        self.conn = conn
        self.event = threading.Event()
        self.peer = None
        self.created = time.time()
        self.pump_done = threading.Event()


class Relay:
    """Bir prosesin ömrü boyu YAŞAYAN, yaddaş-daxili qoşalaşdırma cədvəli.

    QEYD: bu, TƏK Render instansiyası daxilində işləyir (Render Disk-in
    özü artıq tək-instansiyaya məhdudlaşdırdığı üçün — bax plan sənədi).
    Üfüqi miqyaslanma (bir neçə instansiya) altında host və viewer FƏRQLİ
    instansiyalara düşə bilər və bu cədvəl işləməz — hazırkı trafik
    səviyyəsi üçün qəsdən qəbul edilmiş məhdudiyyətdir.
    """

    def __init__(self):
        self._slots: dict[tuple, _Slot] = {}
        self._lock = threading.Lock()
        self._sweep_stop = threading.Event()
        self._sweep_thread = threading.Thread(target=self._sweep_loop, daemon=True)
        self._sweep_thread.start()

    def _sweep_loop(self):
        while not self._sweep_stop.wait(SWEEP_INTERVAL):
            now = time.time()
            with self._lock:
                stale = [
                    k for k, s in self._slots.items()
                    if s.peer is None and now - s.created > SLOT_TIMEOUT
                ]
                for k in stale:
                    del self._slots[k]

    def stop(self):
        self._sweep_stop.set()

    def rendezvous(self, key, my_conn, timeout: float = SLOT_TIMEOUT):
        """`key`-ə görə qarşı tərəfi tapır.

        İlk gələn tərəf `timeout` saniyəyədək gözləyir (ikinci tərəf
        gəlməsə None qaytarır, slot silinir). İkinci gələn tərəf dərhal
        cütləşdirməni tamamlayır və HƏR İKİ tərəfin bir-birinin `conn`-unu
        görməsini təmin edir. Eyni-anda gəlmə TƏK kilidlə həll olunur —
        yalnız bir thread "mən birinciyəm" budağını qazana bilər.
        """
        with self._lock:
            slot = self._slots.get(key)
            if slot is None:
                slot = _Slot(my_conn)
                self._slots[key] = slot
                am_first = True
            else:
                am_first = False

        if am_first:
            if slot.event.wait(timeout):
                return slot.peer
            with self._lock:
                if self._slots.get(key) is slot:
                    del self._slots[key]
            return None

        with self._lock:
            current = self._slots.get(key)
            if current is not slot or current.peer is not None:
                # İlk tərəf bu aralıqda vaxtı bitib silinib (yarış) —
                # YENİDƏN "ilk" kimi başla (öz slotunu yaradaraq gözlə).
                pass
            else:
                del self._slots[key]
                slot.peer = my_conn
                slot.event.set()
                return slot.conn
        return self.rendezvous(key, my_conn, timeout)

    def rendezvous_and_pump(self, key, my_conn, timeout: float = SLOT_TIMEOUT) -> None:
        """`rendezvous()` + `pump()`-u BİRLİKDƏ, TƏHLÜKƏSİZ şəkildə idarə edir.

        VACİB (real tapılmış bug): sadəcə `rendezvous()` çağırıb, hər İKİ
        tərəfin ÖZ-ÖZLƏRİNƏ ayrıca `pump(conn, peer)` çağırması — məsələn
        HTTP handler-in özündə — YALNIZ BİR tərəfin `pump()` çağırmalı
        olduğunu təmin ETMİR. Hər iki tərəf ayrıca `pump()` çağırsa, EYNİ
        iki socket arasında 4 (2×2) thread eyni vaxtda `.recv()`/`.send()`
        edir — klassik race condition: heç bir xəta atılmır, sadəcə hər
        iki tərəf `_read_exact`-də əbədi qalır (bir thread digərinin
        gözlədiyi baytları "oğurlayır"). Yerli test mühitində (aşağı
        gecikmə) bu, təsadüfən "işləyə" bilər, real şəbəkə gecikməsi
        altında (Render kimi) demək olar ki, həmişə heç bir kadr keçmir.

        Ona görə: YALNIZ "ikinci" gələn tərəf `pump()`-ı çağırır. "İlk"
        gələn tərəf (öz HTTP handler thread-i, socket-i AÇIQ saxlamaq
        üçün) sadəcə pump bitənə qədər gözləyir.
        """
        with self._lock:
            slot = self._slots.get(key)
            if slot is None:
                slot = _Slot(my_conn)
                self._slots[key] = slot
                am_first = True
            else:
                am_first = False

        print(f"[relay-debug] key={key} am_first={am_first}")

        if am_first:
            if not slot.event.wait(timeout):
                print(f"[relay-debug] key={key} FIRST timed out waiting for peer")
                with self._lock:
                    if self._slots.get(key) is slot:
                        del self._slots[key]
                try:
                    my_conn.close()
                except Exception:
                    pass
                return
            # İkinci tərəf artıq pump-u başladıb (ya da elə indi başladır)
            # — biz sadəcə o bitənə qədər bu HTTP handler thread-ini
            # (və beləliklə socket-i) açıq saxlayırıq.
            print(f"[relay-debug] key={key} FIRST: peer arrived, waiting on pump_done")
            slot.pump_done.wait()
            print(f"[relay-debug] key={key} FIRST: pump_done set, returning")
            return

        with self._lock:
            current = self._slots.get(key)
            if current is not slot or current.peer is not None:
                pass   # ilk tərəf bu aralıqda vaxtı bitib silinib — aşağıda yenidən "ilk" kimi başla
            else:
                del self._slots[key]
                slot.peer = my_conn
                slot.event.set()
                print(f"[relay-debug] key={key} SECOND: calling pump()")
                try:
                    pump(slot.conn, my_conn)
                finally:
                    print(f"[relay-debug] key={key} SECOND: pump() returned")
                    slot.pump_done.set()
                return
        self.rendezvous_and_pump(key, my_conn, timeout)


def pump(conn_a, conn_b) -> None:
    """İki obyekt arasında kor, 2-istiqamətli bayt ötürməsi.

    Hər ikisi `.recv() -> bytes` (bağlanıbsa istisna atır) və `.send(bytes)`
    metodlarına malik olmalıdır (bax `ws_lite.WSConnection`). Hər hansı
    istiqamət bağlanan kimi DİGƏRİ də bağlanır — bir tərəfin ölməsi bütün
    cütü dağıdır (funksiya hər iki ötürmə thread-i bitənədək BLOKLAYIR,
    çağıran bunu öz thread-ində işə salmalıdır).
    """
    stop = threading.Event()

    def _forward(src, dst, label):
        n = 0
        try:
            while not stop.is_set():
                data = src.recv()
                n += 1
                print(f"[relay-debug] pump/{label}: forwarded msg #{n} ({len(data)} bytes)")
                dst.send(data)
        except Exception as e:
            print(f"[relay-debug] pump/{label}: exception after {n} msgs: {type(e).__name__}: {e}")
        finally:
            stop.set()
            try:
                src.close()
            except Exception:
                pass
            try:
                dst.close()
            except Exception:
                pass

    t1 = threading.Thread(target=_forward, args=(conn_a, conn_b, "a->b"), daemon=True)
    t2 = threading.Thread(target=_forward, args=(conn_b, conn_a, "b->a"), daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
