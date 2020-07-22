
exception Timeout

type key
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
and msec_t = int
and time_spec = {
    sec : sec_t;
    msec : msec_t
}

type tag = int

val ts_zero : time_spec

val ipc_private : key

val ftok : string -> int -> key
val int_of_key : key -> int
val key_of_int : int -> key

module Sem :
    sig
        type t
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
          
        val int_of : t -> int
        val semget : key -> int -> perms -> flag list -> t
        val stat : t -> stat
        val ipc_stat : t -> stat
        val set_ipc_stat : t -> stat -> unit
        val ipc_rmid : t -> unit
        val ipc_info : t -> info
        val info : t -> info
        val get_val : t -> int -> int 
        val set_val : t -> int -> int -> unit
        val get_all : t -> int array
        val set_all : t -> int array -> unit
        val get_pid : t -> int
        val get_ncnt : t -> int -> int
        val get_zcnt : t -> int -> int
        val rmid_noexc : t -> unit

        val op : t -> buf array -> unit
        val timedop : t -> buf array -> time_spec -> unit
        val timed_op : t -> buf array -> time_spec -> unit

        val wait_op : int -> buf array
        val signal_op : int -> buf array

        val clear : int -> int -> unit

        val make : ?nsems:int -> ?perms:perms -> ?flags:flag list -> ?rm:bool -> key -> t
        val make_opt : ?nsems:int -> ?perms:perms -> ?flags:flag list -> ?rm:bool -> (string * int) option -> t
        val create : ?key:string * int -> ?nsems:int -> ?perms:perms -> ?flags:flag list -> ?rm:bool -> unit -> t

        val reset : ?num:int -> t -> unit
        val init : ?key:string * int -> ?nsems:int -> ?perms:perms -> ?flags:flag list -> unit -> t
        val key_init : ?nsems:int -> ?perms:perms -> ?flags:flag list -> key -> t

        val wait : ?num:int -> t -> unit
        val signal : ?num:int -> t -> unit
        val timed_wait : ?num:int -> ?ts:time_spec -> t -> unit
        val guard : t -> ('a -> 'b) -> 'a -> 'b
        val timed_guard : ?ts:time_spec -> t -> ('a -> 'b) -> 'a -> 'b

        val kguard : ?nsems:int -> ?perms:perms -> ?flags:flag list -> ?rm:bool -> key -> ('a -> 'b) -> 'a -> 'b
        val sguard : ?key:string * int -> ?perms:perms -> ?flags:flag list -> ?rm:bool -> ('a -> 'b) -> 'a -> 'b
        val timed_sguard : ?key:string * int -> ?perms:perms -> ?flags:flag list -> ?rm:bool -> ?ts:time_spec -> 
                ('a -> 'b) -> 'a -> 'b
        val timed_key_guard : ?perms:perms -> ?flags:flag list -> ?rm:bool -> ?ts:time_spec -> key -> 
                ('a -> 'b) -> 'a -> 'b
    end

module Msg :
    sig
        type t 

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

        val maxlen : int

        val int_of : t -> int
        val msgget : key -> int -> flag list -> t
        val stat : t -> stat 
        val ipc_stat : t -> stat
        val ipc_set : t -> stat -> unit
        val ipc_rmid : t -> unit
        val ipc_info : t -> info
        val info : t -> info

        val sendmsg : t -> msg -> flg list -> unit
        val recvmsg : t -> tag -> int -> flg list -> msg

        val send_msg : ?flgs:flg list -> t -> msg -> unit
        val recv_msg : ?flgs:flg list -> ?tag:tag -> ?len:int -> t -> msg

        val send_bytes : ?flgs:flg list -> ?tag:tag -> t -> bytes -> unit
        val recv_bytes : ?flgs:flg list -> ?tag:tag -> ?len:int -> t -> int * bytes

        val send : ?flgs:flg list -> ?tag:tag -> t -> string -> unit
        val recv : ?flgs:flg list -> ?tag:tag -> ?len:int -> t -> int * string
        val recv_tag : ?flgs:flg list -> ?len:int -> tag -> t -> string

        val send_val : ?flgs:flg list -> ?tag:tag -> t -> 'a -> int
        val recv_val : ?flgs:flg list -> ?tag:tag -> ?len:int -> t -> int * 'a
        val recv_tag_val : ?flgs:flg list -> tag -> t -> 'a

        val rmid_noexc : t -> unit

        val make : ?perms:int -> ?flags:flag list -> ?rm:bool -> key -> t
        val create : ?key:key_t -> ?perms:int -> ?flags:flag list -> ?rm:bool -> unit -> t
        val cfg_make : ?perms:int -> ?flags:flag list -> ?rm:bool -> (unit -> key) -> t

        type _ g_rsp = 
            | G_tag : tag -> 'a g_rsp
            | G : (tag * 'a) g_rsp
        val g_send : ?tag:tag -> t -> 'a -> int
        val g_recv : t -> 'a g_rsp -> 'a
    end

module Shm : 
    sig
        type t 
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

        val int_of : t -> int
        val shmget : key -> int -> perms -> flag list -> t
        val make : ?perms:perms -> ?flags:flags -> int -> key -> t
        val make_opt : ?perms:perms -> ?flags:flags -> int -> (string * int) option -> t
        val create : ?key:(string * int) -> ?perms:perms -> ?flags:flags -> int -> t
        val ipc_stat : t -> stat
        val ipc_set : t -> stat -> unit
        val ipc_rmid : t -> unit
        val ipc_info : t -> ipc_info
        val info : t -> info
        val stat : t -> stat
        val lock : t -> unit
        val unlock : t -> unit
        val attach : t -> flg list -> addr
        val detach : addr -> unit 

        val get_bytes : addr -> int -> bytes
        val sub : addr -> int -> int -> bytes 
        val get_ch : addr -> int -> char
        val set_ch : addr -> int -> char -> unit
        val add_bytes : addr -> int -> bytes -> unit
        val clear : addr -> int -> int -> char -> unit
        val indexp : addr -> int -> int -> char -> int

        val use_addr : ?flgs:flg list -> t -> (addr -> 'a) -> 'a

        val get : ?sz:int -> addr -> bytes
        val set_val : ?ofs:int -> addr -> 'a -> int
        val get_val : ?sz:int -> ?ofs:int -> addr -> 'a
        val index : ?ofs:int -> addr -> int -> char -> int

        val guard : Sem.t * t -> (addr -> 'a) -> 'a
        val condition : Sem.t * t -> (addr -> bool) -> 'a -> 'a
    end 

module ShmBuffer :
    sig
        type t
        val make : ?flags:Shm.flag list -> ?perms:int -> ?flgs:Shm.flg list -> int -> key -> t
        val create : ?key:(string * int) -> ?flags:Shm.flag list -> ?perms:int -> ?flgs:Shm.flg list -> int -> t
        val close : t -> unit
        val reset : t -> unit
        val length : t -> int

        val contents : t -> bytes
        val full_contents : t -> bytes
        val nth : t -> int -> char
        val set_nth : t -> int -> char -> unit
        val sub : ?ofs:int -> ?len:int -> t -> bytes

        val index : ?ofs:int -> ?idx:char -> t -> int
        val index_opt : ?ofs:int -> ?idx:char -> t -> int option
        val index_sub : ?ofs:int -> ?idx:char -> t -> bytes

        val add_char : t -> char -> unit
        val add_bytes : t -> bytes -> unit
        val add_string : t -> string -> unit
        val add_buffer : t -> Buffer.t -> unit

        val split_ch : ?ch:char -> t -> bytes list
    end
