open Unix

exception Timeout

type key = int
type key_t = string * int

type flag = 
    | Create
    | Excl
    | NoWait

type flags = flag list

type perms = int
type ipc_perms = {
    key : key;
    uid : int;
    gid : int;
    cuid : int;
    cgid : int;
    mode : perms;
    seq : int
}

type sec_t = float
type msec_t = int
type time_spec = {
    sec : sec_t;
    msec : msec_t
}

type tag = int

let ts_zero = { sec = 0.0; msec = 0 }

external ipcPrivate : unit -> key = "cipc_private"
let ipc_private = ipcPrivate()

external ftok : string -> int -> key = "cipc_ftok"
let int_of_key k = k
let key_of_int k = k

module Sem =
    struct
        type t = int
        type stat = {
            perms : ipc_perms;
            otime : sec_t;
            ctime : sec_t;
            nsems : int
        }
        type info = {
            map_entries : int;
            max_sem_sets : int;
            total_sems : int;
            max_undos : int;
            max_sems_in_set : int;
            max_ops_semop : int;
            max_undo_proc : int;
            undo_size : int;
            max_sem_val : int;
            max_adj_val : int
        }

        type flg = 
            | NoWait
            | Undo
        type buf = {
            num : int;
            op : int;
            flgs : flg list
        }

        let int_of s : int =  s
        external semget : key -> int -> perms -> flag list -> t = "cipc_semget"
        external stat : t -> stat = "cipc_sem_stat"
        external ipc_stat : t ->stat = "cipc_sem_ipc_stat"
        external set_ipc_stat : t -> stat -> unit = "cipc_sem_ipc_set"
        external ipc_rmid : t -> unit = "cipc_sem_ipc_rmid"
        external ipc_info : t -> info = "cipc_sem_ipc_info"
        external info : t -> info = "cipc_sem_info"
        external get_val : t -> int -> int = "cipc_sem_getval"
        external set_val : t -> int -> int -> unit = "cipc_sem_setval"
        external get_all : t -> int array = "cipc_sem_get_all"
        external set_all : t -> int array -> unit = "cipc_sem_set_all"
        external get_pid : t -> int = "cipc_sem_get_pid"
        external get_ncnt : t -> int -> int = "cipc_sem_get_ncnt"
        external get_zcnt : t -> int -> int = "cipc_sem_get_zcnt"
        let rmid_noexc sem = 
            try ipc_rmid sem
            with Unix_error(EINVAL, _, _) -> ()

        external op : t -> buf array -> unit = "cipc_semop"
        external timedop : t -> buf array -> time_spec -> unit = "cipc_semtimedop"
        let timed_op sem op tsp =
            try timedop sem op tsp
            with Unix_error(EAGAIN, _, _) -> raise Timeout

        let wait_op num = [| {num=num; op=0; flgs=[]}; {num=num; op=1; flgs=[]} |]
        let signal_op num = [| {num=num; op=(-1); flgs=[NoWait]} |]

        let clear num sem = set_val sem num 0
        let rmid sem = rmid_noexc sem

        let prim_new_sem key nsems perms flags rm = 
            let s = semget key nsems perms flags in
            if rm then at_exit (fun () -> rmid s) else ();
            s
        let prim_create key nsems perms flags rm =
            try prim_new_sem key nsems perms flags rm
            with Unix_error(ENOENT, _, _) -> prim_new_sem key nsems perms (Create::flags) rm

        let make ?(nsems=1) ?(perms=0o744) ?(flags=[]) ?(rm=false) key = prim_create key nsems perms flags rm
        let make_opt ?(nsems=1) ?(perms=0o744) ?(flags=[]) ?(rm=false) key = 
            match key with
            | None -> make ~nsems ~perms ~flags ~rm ipc_private
            | Some (path, id) -> make ~nsems ~perms ~flags ~rm (ftok path id)
        let create ?key ?(nsems=1) ?(perms=0o744) ?(flags=[]) ?(rm=false) () = 
            make_opt ~nsems ~perms ~flags ~rm key

        let zero = ts_zero

        let wait ?(num=0) sem = op sem (wait_op num)
        let signal ?(num=0) sem =  timed_op sem (signal_op num) zero
        let timed_wait ?(num=0) ?(ts=zero) sem = timed_op sem (wait_op num) ts

        let reset ?(num=0) sem = set_val sem num 0
        let key_init_prim mk arg = 
            let sem = mk arg in
            reset sem;
            sem
        let init ?key ?(nsems=1) ?(perms=0o744) ?(flags=[]) () =
            key_init_prim (make_opt ~nsems ~perms ~flags) key
        let key_init ?(nsems=1) ?(perms=0o744) ?(flags=[]) key = 
            key_init_prim (make ~nsems ~perms ~flags) key

        let guarder wtfn sem fn arg =
            wtfn sem;
            try
                let rc = fn arg in
                signal sem;
                rc
            with e ->
                (* (try set_val sem 0 0 with _ -> ()); *)
                (try signal sem with _ -> ());
                raise e

        let guard sem fn arg = guarder wait sem fn arg
        let timed_guard ?(ts=zero) sem fn arg = guarder (timed_wait ~ts) sem fn arg

        let kguard ?(nsems=1) ?(perms=0o744) ?(flags=[]) ?(rm=false) key fn arg =
            guard (make ~nsems ~perms ~flags ~rm key) fn arg
        let sguard ?key ?(perms=0o744) ?(flags=[]) ?(rm=false) fn args = 
            guard (make_opt ~nsems:1 ~perms ~flags ~rm key) fn args
        let timed_sguard ?key ?(perms=0o744) ?(flags=[]) ?(rm=false) ?(ts=zero) fn args = 
            timed_guard ~ts (make_opt ~nsems:1 ~perms ~flags ~rm key) fn args
        let timed_key_guard ?(perms=0o744) ?(flags=[]) ?(rm=false) ?(ts=zero) key fn args = 
            timed_guard ~ts (make ~perms ~flags ~rm key) fn args
    end

module Msg = 
    struct
        type t = int

        type stat = {
            perms : ipc_perms;
            stime : sec_t;
            rtime : sec_t;
            ctime : sec_t;
            cur_bytes : int;
            cur_msgs : int;
            max_bytes : int;
            snd_pid : int;
            rcv_pid : int
        }
        type info = {
            pool_sz : int;
            entries : int;
            b_per_msg : int;
            b_write : int;
            max_queues : int;
            seg_sz : int;
            total_msgs : int;
            max_segs : int
        }
        type flg = 
            | NoWait
            | Copy
            | Except
            | Truncate
        type msg = {
            mtype : tag;
            mtext : bytes
        }

        let maxlen = 65536

        let int_of m : int = m
        external msgget : key -> int -> flag list -> t = "cipc_msgget"
        external stat : t -> stat = "cipc_msg_stat"
        external ipc_stat : t -> stat = "cipc_msg_ipc_stat"
        external ipc_set : t -> stat -> unit = "cipc_msg_ipc_set"
        external ipc_rmid : t -> unit = "cipc_msg_ipc_rmid"
        external ipc_info : t -> info = "cipc_msg_ipc_info"
        external info : t -> info = "cipc_msg_info"
       
        external sendmsg : t -> msg -> flg list -> unit = "cipc_msg_send"
        external recvmsg : t -> tag -> int -> flg list -> msg = "cipc_msg_recv"

        let send_msg ?(flgs=[]) m msg = sendmsg m msg flgs
        let recv_msg ?(flgs=[]) ?(tag=0) ?(len=maxlen) m = recvmsg m tag len flgs

        let send_bytes ?(flgs=[]) ?(tag=1) m mtext = sendmsg m {mtype=tag; mtext=mtext} flgs
        let recv_bytes ?(flgs=[]) ?(tag=0) ?(len=maxlen) m = 
            let msg = recvmsg m tag len flgs in
            msg.mtype, msg.mtext

        let send ?(flgs=[]) ?(tag=1) m mtext = 
            send_msg ~flgs m {mtype=tag; mtext=Bytes.of_string mtext}
        let recv ?(flgs=[]) ?(tag=0) ?(len=maxlen) m = 
            let msg = recv_msg ~flgs ~tag ~len m in
            msg.mtype, Bytes.to_string msg.mtext
        let recv_tag ?(flgs=[]) ?(len=maxlen) tag m = 
            snd (recv ~flgs ~tag ~len m)

        let send_val ?(flgs=[]) ?(tag=1) m obj = 
            let msg = {mtype=tag; mtext=(Marshal.to_bytes obj [])} in
            send_msg ~flgs m msg;
            Bytes.length msg.mtext
        let recv_val ?(flgs=[]) ?(tag=0) ?(len=maxlen) m = 
            let msg = recv_msg ~flgs ~tag ~len m in
            msg.mtype, (Marshal.from_bytes msg.mtext 0)
        let recv_tag_val ?(flgs=[]) tag m = 
            snd (recv_val ~flgs ~tag m)

        let rmid_noexc msg = 
            try ipc_rmid msg
            with Unix_error(EINVAL, _, _) -> ()

        let prim_new key perms flags rm = 
            let mq = msgget key perms flags in
            if rm then at_exit (fun () -> rmid_noexc mq);
            mq
        let prim_create key perms flags rm = 
            try prim_new key perms flags rm
            with Unix_error(ENOENT, _ , _) -> prim_new key perms (Create::flags) rm

        let make ?(perms=0o744) ?(flags=[]) ?(rm=false) key = prim_create key perms flags rm
        let create ?key ?(perms=0o744) ?(flags=[]) ?(rm=false) () = 
            match key with
            | None -> prim_create ipc_private perms flags rm
            | Some (file, id) -> prim_create (ftok file id) perms flags rm
        let cfg_make ?(perms=0o744) ?(flags=[]) ?(rm=false) (get : unit -> key) = 
            prim_create (get()) perms flags rm 

        type _ g_rsp = 
            | G_tag : tag -> 'a g_rsp
            | G : (tag * 'a) g_rsp
        let g_send ?tag mq msg =
            match tag with
            | None -> send_val mq msg
            | Some tag -> send_val ~tag mq msg
        let g_recv (type a) (mq : t) (g : a g_rsp) : a =
            match g with
            | G_tag tag -> snd (recv_val ~tag mq)
            | G -> recv_val mq
    end

module Shm = 
    struct
        type t = int
        type flag =
            | Create
            | Excl
            | Dest
            | Locked
            | HugeTLB
            | NoReserve
        type flags = flag list

        type stat = {
            perms : ipc_perms;
            seg_sz : int;
            atime : sec_t;
            dtime : sec_t;
            ctime : sec_t;
            creator_pid : int;
            last_pid : int;
            num_attach : int64
        }
        type ipc_info = {
            max_seg_sz : int64;
            min_seg_sz : int64;
            max_segs : int64;
            max_proc_segs : int64;
            max_pg : int64
        }
        type info = {
            used_ids : int;
            total_pg : int64;
            rss_pg : int64;
            swap_pg : int64
        }

        type flg = 
            | Exec
            | RdOnly
            | ReMap

        type addr
        
        let int_of s : int = s
        external shmget : key -> int -> perms -> flag list -> t = "cipc_shmget"
        let make ?(perms=0o644) ?(flags=[]) sz key = 
            try shmget key sz perms flags
            with 
            | Unix_error (EACCES, _, _) -> shmget key sz perms (Create::flags)
            | Unix_error (ENOENT, _, _) -> shmget key sz perms (Create::flags)
        let make_opt ?(perms=0o644) ?(flags=[]) sz = function
            | None -> make ~perms ~flags sz ipc_private
            | Some (f, id) -> make ~perms ~flags sz (ftok f id)
        let create ?key ?(perms=0o644) ?(flags=[Create]) sz = make_opt ~perms ~flags sz key
        external ipc_stat : t -> stat = "cipc_shm_ipc_stat"
        external ipc_set : t -> stat -> unit = "cipc_shm_ipc_set"
        external ipc_rmid : t -> unit = "cipc_shm_ipc_rmid"
        external ipc_info : t -> ipc_info = "cipc_shm_ipc_info"
        external info : t -> info = "cipc_shm_info"
        external stat : t -> stat = "cipc_shm_stat"
        external lock : t -> unit = "cipc_shm_lock"
        external unlock : t -> unit = "cipc_shm_unlock"
        external attach : t -> flg list -> addr = "cipc_shm_attach"
        external detach : addr -> unit = "cipc_shm_detach"

        external get_bytes : addr -> int -> bytes = "cipc_shm_addr_get_bytes"
        external sub : addr -> int -> int -> bytes = "cipc_shm_addr_sub"
        external get_ch : addr -> int -> char = "cipc_shm_addr_get_ch"
        external set_ch : addr -> int -> char -> unit = "cipc_shm_addr_set_ch"
        external add_bytes : addr -> int -> bytes -> unit = "cipc_shm_addr_add_bytes"
        external clear : addr -> int -> int -> char -> unit = "cipc_shm_addr_clear"
        external indexp : addr -> int -> int -> char -> int = "cipc_shm_addr_indexp"

        let use_addr ?(flgs=[]) shm fn = 
            let addr = attach shm flgs in
            try
                let rc = fn addr in
                detach addr;
                rc
            with e ->
                (try detach addr with _ -> ());
                raise e

        let get ?(sz=1024) addr = 
            let rec loop len =
                let msg = get_bytes addr len in
                match Bytes.index_opt msg '\000' with
                | None -> loop (len + sz)
                | Some pos -> Bytes.sub msg 0 pos
            in
            if sz <= 0 then Bytes.of_string ""
            else loop sz
        let set_val ?(ofs=0) addr obj = 
            let msg = Marshal.to_bytes obj [] in
            add_bytes addr ofs msg;
            Bytes.length msg
        let get_val ?(sz=1024) ?(ofs=0) addr =
            let msg = sub addr ofs sz in
            Marshal.from_bytes msg 0
        let index ?(ofs=0) addr maxlen ch = 
            match indexp addr maxlen ofs ch with
            | (-1) -> raise Not_found
            | pos -> pos

        let guard (sem, shm) fn = Sem.guard sem (use_addr shm) fn

        let condition (sem, shm) cond v = 
            let taker addr = 
                if cond addr then 
                    let msg = get_val addr in
                    ignore (set_val addr v);
                    msg
                else
                    v
            in
            guard (sem, shm) taker
    end

module ShmBuffer =
    struct
        type t = {
            shm : Shm.t;
            addr : Shm.addr;
            sz : int;
            mutable pos : int
        }
        let make ?(flags=[]) ?(perms=0o644) ?(flgs=[]) sz key =
            let shm = Shm.make ~flags ~perms sz key in
            let addr = Shm.attach shm flgs in
            {
                shm = shm;
                addr = addr;
                sz = sz;
                pos = 9
            }
        let create ?key ?(flags=[]) ?(perms=0o644) ?(flgs=[]) sz = 
            match key with
            | None -> make ~flags ~perms ~flgs sz ipc_private
            | Some (f, id) -> make ~flags ~perms ~flgs sz (ftok f id)

        let close m = 
            Shm.detach m.addr;
            Shm.ipc_rmid m.shm
        let reset m = m.pos <- 0
        let length m = m.pos

        let contents m = Shm.get ~sz:m.pos m.addr
        let full_contents m = Shm.get_bytes m.addr m.sz 
        let nth m pos = 
            if pos + 1 > m.sz then raise (Invalid_argument "nth")
            else Shm.get_ch m.addr pos
        let set_nth m pos ch = 
            if pos > m.sz then raise (Invalid_argument "set_nth")
            else Shm.set_ch m.addr pos ch
        let sub ?(ofs=0) ?len m = 
            match ofs, len with
            | ofs, _ when ofs >= m.sz -> raise (Invalid_argument "sub")
            | ofs, Some len when (ofs+len) > m.sz -> Shm.sub m.addr ofs (m.sz - ofs)
            | ofs, None -> Shm.sub m.addr ofs (m.sz - ofs)
            | ofs, Some len -> Shm.sub m.addr ofs len

        let index ?(ofs=0) ?(idx='\000') m = Shm.index ~ofs m.addr m.sz idx
        let index_opt ?(ofs=0) ?(idx='\000') m = 
            try Some (index ~ofs ~idx m)
            with Not_found -> None
        let index_sub ?(ofs=0) ?(idx='\000') m = 
            if ofs > m.sz then raise (Invalid_argument "index_sub")
            else
                match index_opt ~ofs ~idx m with
                | None -> sub ~ofs m
                | Some idx -> sub ~ofs ~len:(idx - ofs) m

        let add_char m ch = 
            if (1 + m.pos) > m.sz then raise (Invalid_argument "add_char")
            else (Shm.set_ch m.addr m.pos ch; m.pos <- m.pos + 1)
        let add_bytes m b = 
            let blen = Bytes.length b in
            let b = 
                if (m.pos + blen) > m.sz then Bytes.sub b 0 (m.sz - m.pos)
                else b
            in
            Shm.add_bytes m.addr m.pos b;
            m.pos <- m.pos + (Bytes.length b)
        let add_string m s = add_bytes m (Bytes.of_string s)
        let add_buffer m b = add_string m (Buffer.contents b)

        let split_ch ?(ch='\000') c = 
            let rec loop ofs =
                if ofs > c.sz then []
                else
                    match index_opt ~ofs ~idx:ch c with
                    | None -> (sub ~ofs ~len:c.sz c) :: []
                    | Some pos -> 
                        let s = sub ~ofs ~len:(pos-ofs) c in
                        s :: (loop (1 + pos + ofs))
            in
            loop 0
    end

