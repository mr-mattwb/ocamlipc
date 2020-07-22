#include <stdio.h>
#include <string.h>

#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/errno.h>
#include <sys/sem.h>
#include <sys/msg.h>
#include <sys/shm.h>
#include <sys/stat.h>

#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/fail.h>
#include <caml/alloc.h>
#include <caml/config.h>
#include <caml/custom.h>
#include <caml/callback.h>
#include <caml/unixsupport.h>

#define Val_key(k)              (Val_int(k))
#define Key_val(v)              ((key_t)Int_val(v))

static int cipc_flags[] = {
    IPC_CREAT,
    IPC_EXCL,
    IPC_NOWAIT
};
#define IpcFlags_val(v)         (caml_convert_flag_list(v, cipc_flags))

static int cipc_perms[] = {
    S_IRUSR,
    S_IWUSR,
    S_IXUSR,
    S_IRWXU,
    S_IRGRP,
    S_IWGRP,
    S_IXGRP,
    S_IRWXG,
    S_IROTH,
    S_IWOTH,
    S_IXOTH,
    S_IRWXO
};
#define IpcPerms_val(v)         (caml_convert_flag_list(v, cipc_perms))

#define Val_sem(s)              (Val_int(s))
#define Sem_val(v)              (Int_val(v))

static int cipc_semflags[] = {
    IPC_NOWAIT,
    SEM_UNDO
};
#define SemFlags_val(v)         (caml_convert_flag_list(v, cipc_semflags))

#define Ipc_error(f, v)               (unix_error(errno, f, caml_copy_string(v)))
#define Semctl_error(v)                 (Ipc_error("semctl()", v))
#define Semop_error(v)                  (Ipc_error("semop()", v))

CAMLprim value cipc_private() {
    CAMLparam0();
    CAMLreturn(Val_int(IPC_PRIVATE));
}
static key_t cipc_ipc_private = Val_int(IPC_PRIVATE);


CAMLprim value Val_ipc_perms(struct ipc_perm perms)
{
    CAMLparam0();
    CAMLlocal1(v_perms);
    v_perms = caml_alloc_tuple(7);
    Store_field(v_perms, 0, Val_int(perms.__key));
    Store_field(v_perms, 1, Val_int(perms.uid));
    Store_field(v_perms, 2, Val_int(perms.gid));
    Store_field(v_perms, 3, Val_int(perms.cuid));
    Store_field(v_perms, 4, Val_int(perms.cgid));
    Store_field(v_perms, 5, Val_int(perms.mode));
    Store_field(v_perms, 6, Val_int(perms.__seq));
    CAMLreturn(v_perms);
}
CAMLprim value Ipc_perms_val(value v_perms, struct ipc_perm *perms)
{
    CAMLparam1(v_perms);
    perms->__key = Int_val(Field(v_perms, 0));
    perms->uid = Int_val(Field(v_perms, 1));
    perms->gid = Int_val(Field(v_perms, 2));
    perms->cuid = Int_val(Field(v_perms, 3));
    perms->cgid = Int_val(Field(v_perms, 4));
    perms->mode = Int_val(Field(v_perms, 5));
    perms->__seq = Int_val(Field(v_perms, 6));
    CAMLreturn(Val_unit);
}

#define Val_time(v)         (caml_copy_double(v))
#define Time_val(v)         (Double_val(v))

CAMLprim value Val_semid(struct semid_ds ds)
{
    CAMLparam0();
    CAMLlocal1(v_ds);
    v_ds = caml_alloc_tuple(4);
    Store_field(v_ds, 0, Val_ipc_perms(ds.sem_perm));
    Store_field(v_ds, 1, Val_time(ds.sem_otime));
    Store_field(v_ds, 2, Val_time(ds.sem_ctime));
    Store_field(v_ds, 3, Val_int(ds.sem_nsems));
    CAMLreturn(v_ds);
}
CAMLprim value Semid_val(value v_ds, struct semid_ds *ds)
{
    CAMLparam1(v_ds);
    Ipc_perms_val(Field(v_ds, 0), &ds->sem_perm);
    ds->sem_otime = Double_val(Field(v_ds, 1));
    ds->sem_ctime = Double_val(Field(v_ds, 2));
    ds->sem_nsems = Int_val(Field(v_ds, 3));
    CAMLreturn(Val_unit);
}

CAMLprim value Val_seminfo(struct seminfo info)
{
    CAMLparam0();
    CAMLlocal1(v_info);
    v_info = caml_alloc_tuple(10);
    Store_field(v_info, 0, Val_int(info.semmap));
    Store_field(v_info, 1, Val_int(info.semmni));
    Store_field(v_info, 2, Val_int(info.semmns));
    Store_field(v_info, 3, Val_int(info.semmnu));
    Store_field(v_info, 4, Val_int(info.semmsl));
    Store_field(v_info, 5, Val_int(info.semopm));
    Store_field(v_info, 6, Val_int(info.semume));
    Store_field(v_info, 7, Val_int(info.semusz));
    Store_field(v_info, 8, Val_int(info.semvmx));
    Store_field(v_info, 9, Val_int(info.semaem));
    CAMLreturn(v_info);
}

CAMLprim value Sembuf_val(value v_sop, struct sembuf *buf)
{
    CAMLparam1(v_sop);
    buf->sem_num = Int_val(Field(v_sop, 0));
    buf->sem_op = Int_val(Field(v_sop, 1));
    buf->sem_flg = SemFlags_val(Field(v_sop, 2));
    CAMLreturn(Val_unit);
}

CAMLprim value Timespec_val(value v_tsp, struct timespec *tsp)
{
    CAMLparam1(v_tsp);
    tsp->tv_sec = Time_val(Field(v_tsp, 0));
    tsp->tv_nsec = Long_val(Field(v_tsp, 1));
    CAMLreturn(Val_unit);
}
CAMLprim value Val_timespec(struct timespec tsp)
{
    CAMLparam0();
    CAMLlocal1(v_tsp);
    Store_field(v_tsp, 0, Val_time(tsp.tv_sec));
    Store_field(v_tsp, 1, Val_long(tsp.tv_nsec));
    CAMLreturn(v_tsp);
}

#define Msg_val(v)              (Int_val(v))
#define Val_msg(v)              (Val_int(v))
#define Msgctl_error(v)         (unix_error(errno, "msgctl()", caml_copy_string(v)))

#define Val_curbytes(v)             (Val_int(v))
#define Curbytes_val(v)         (Int_val(v))
#define Val_msg_qnum(v)         (Val_int(v))
#define Msg_qnum_val(v)         (Int_val(v))
#define Val_qbytes(v)           (Val_int(v))
#define Qbytes_val(v)           (Int_val(v))
#define Val_pid(v)              (Val_int(v))
#define Pid_val(v)              (Int_val(v))

CAMLprim value Val_msqid(struct msqid_ds ds)
{
    CAMLparam0();
    CAMLlocal1(v_ds);
    v_ds = alloc_tuple(9);
    Store_field(v_ds, 0, Val_ipc_perms(ds.msg_perm));
    Store_field(v_ds, 1, Val_time(ds.msg_stime));
    Store_field(v_ds, 2, Val_time(ds.msg_rtime));
    Store_field(v_ds, 3, Val_time(ds.msg_ctime));
    Store_field(v_ds, 4, Val_curbytes(ds.__msg_cbytes));
    Store_field(v_ds, 5, Val_msg_qnum(ds.msg_qnum));
    Store_field(v_ds, 6, Val_qbytes(ds.msg_qbytes));
    Store_field(v_ds, 7, Val_pid(ds.msg_lspid));
    Store_field(v_ds, 8, Val_pid(ds.msg_lrpid));
    CAMLreturn(v_ds);
}
CAMLprim value Msqid_val(value v_ds, struct msqid_ds *ds)
{
    CAMLparam1(v_ds);
    Ipc_perms_val(Field(v_ds, 0), &ds->msg_perm);
    ds->msg_stime = Time_val(Field(v_ds, 1));
    ds->msg_rtime = Time_val(Field(v_ds, 2));
    ds->msg_ctime = Time_val(Field(v_ds, 3));
    ds->__msg_cbytes = Curbytes_val(Field(v_ds, 4));
    ds->msg_qnum = Msg_qnum_val(Field(v_ds, 5));
    ds->msg_qbytes = Qbytes_val(Field(v_ds, 6));
    ds->msg_lspid = Pid_val(Field(v_ds, 7));
    ds->msg_lrpid = Pid_val(Field(v_ds, 8));
    CAMLreturn(Val_unit);
}
CAMLprim value Val_msginfo(struct msginfo info)
{
    CAMLparam0();
    CAMLlocal1(v_info);
    v_info = alloc_tuple(8);
    Store_field(v_info, 0, Val_int(info.msgpool));
    Store_field(v_info, 1, Val_int(info.msgmap));
    Store_field(v_info, 2, Val_int(info.msgmax));
    Store_field(v_info, 3, Val_int(info.msgmnb));
    Store_field(v_info, 4, Val_int(info.msgmni));
    Store_field(v_info, 5, Val_int(info.msgssz));
    Store_field(v_info, 6, Val_int(info.msgtql));
    Store_field(v_info, 7, Val_int(info.msgseg));
    CAMLreturn(v_info);
}

int cipc_msg_flags[] = {
    IPC_NOWAIT,
    MSG_COPY,
    MSG_EXCEPT,
    MSG_NOERROR
};
#define MsgFlags_val(v)             (caml_convert_flag_list(v, cipc_msg_flags))

int cipc_shmget_flags[] = {
    IPC_CREAT,
    IPC_EXCL,
    SHM_DEST,
    SHM_LOCKED,
    SHM_HUGETLB,
    SHM_NORESERVE
};
#define ShmgetFlags_val(v)              (caml_convert_flag_list(v, cipc_shmget_flags))

#define Val_shm(v)                      (Val_int(v))
#define Shm_val(v)                      (Int_val(v))

#define Val_size(v)                     (Val_int(v))
#define Size_val(v)                     (Int_val(v))

#define Val_shmatt(v)                   (caml_copy_int64(v))
#define Shmatt_val(v)                   (Int64_val(v))

CAMLprim value Val_shmid(struct shmid_ds ds)
{
    CAMLparam0();
    CAMLlocal1(v_ds);
    v_ds = alloc_tuple(8);
    Store_field(v_ds, 0, Val_ipc_perms(ds.shm_perm));
    Store_field(v_ds, 1, Val_size(ds.shm_segsz));
    Store_field(v_ds, 2, Val_time(ds.shm_atime));
    Store_field(v_ds, 3, Val_time(ds.shm_dtime));
    Store_field(v_ds, 4, Val_time(ds.shm_ctime));
    Store_field(v_ds, 5, Val_pid(ds.shm_cpid));
    Store_field(v_ds, 6, Val_pid(ds.shm_lpid));
    Store_field(v_ds, 7, Val_shmatt(ds.shm_nattch));
    CAMLreturn(v_ds);
}
CAMLprim value Shmid_val(value v_ds, struct shmid_ds *ds)
{
    CAMLparam1(v_ds);
    Ipc_perms_val(Field(v_ds, 0), &ds->shm_perm);
    ds->shm_segsz = Size_val(Field(v_ds, 1));
    ds->shm_atime = Time_val(Field(v_ds, 2));
    ds->shm_dtime = Time_val(Field(v_ds, 3));
    ds->shm_ctime = Time_val(Field(v_ds, 4));
    ds->shm_cpid = Pid_val(Field(v_ds, 5));
    ds->shm_lpid = Pid_val(Field(v_ds, 6));
    ds->shm_nattch = Shmatt_val(Field(v_ds, 7));
    CAMLreturn(Val_unit);
}
#define Shmctl_error(v)                 (unix_error(errno, "shmctl()", caml_copy_string(v)))

#define Val_shmUL(v)                    (caml_copy_int64(v))

CAMLprim value Val_shminfo(struct shminfo info)
{
    CAMLparam0();
    CAMLlocal1(v_info);
    v_info = alloc_tuple(5);
    Store_field(v_info, 0, Val_shmUL(info.shmmax));
    Store_field(v_info, 1, Val_shmUL(info.shmmin));
    Store_field(v_info, 2, Val_shmUL(info.shmmni));
    Store_field(v_info, 3, Val_shmUL(info.shmseg));
    Store_field(v_info, 4, Val_shmUL(info.shmall));
    CAMLreturn(v_info);
}
CAMLprim value Val_shm_info(struct shm_info info)
{
    CAMLparam0();
    CAMLlocal1(v_info);
    v_info = alloc_tuple(4);
    Store_field(v_info, 0, Val_int(info.used_ids));
    Store_field(v_info, 1, Val_shmUL(info.shm_tot));
    Store_field(v_info, 2, Val_shmUL(info.shm_rss));
    Store_field(v_info, 3, Val_shmUL(info.shm_swp));
    CAMLreturn(v_info);
}

static int cipc_shm_flags[] = {
    SHM_EXEC,
    SHM_RDONLY,
    SHM_REMAP
};
#define ShmFlags_val(v)         (caml_convert_flag_list(v, cipc_shm_flags))

#define Addr_val(v)             ((void *)v)
#define Val_addr(v)             ((value)v)

CAMLprim value cipc_ftok(value v_path, value v_proj_id) 
{
    CAMLparam2(v_path, v_proj_id);
    key_t key;
    key = ftok(String_val(v_path), Int_val(v_proj_id));
    if (key == -1) 
    { 
        unix_error(errno, "ftok()", v_path); 
    }
    CAMLreturn(Val_key(key));
}

CAMLprim value cipc_semget(value v_key, value v_nsems, value v_perms, value v_semflg)
{
    CAMLparam4(v_key, v_nsems, v_perms, v_semflg);
    int rc = semget(Key_val(v_key), Int_val(v_nsems), Int_val(v_perms) | IpcFlags_val(v_semflg));
    if (rc == -1)
    {
        unix_error(errno, "semget()", caml_copy_string(""));
    }
    CAMLreturn(Val_sem(rc));
}

CAMLprim value cipc_sem_stat(value v_sem)
{
    CAMLparam1(v_sem);
    struct semid_ds ds;
    int rc = semctl(Key_val(v_sem), 0, SEM_STAT, &ds);
    if (rc == -1)
    {
        unix_error(errno, "semctl()", caml_copy_string("SEM_STAT"));
    }
    CAMLreturn(Val_semid(ds));
}
CAMLprim value cipc_sem_ipc_stat(value v_sem)
{
    CAMLparam1(v_sem);
    struct semid_ds ds;
    int rc = semctl(Key_val(v_sem), 0, IPC_STAT, &ds);
    if (rc == -1)
    {
        unix_error(errno, "semctl()", caml_copy_string("IPC_STAT"));
    }
    CAMLreturn(Val_semid(ds));
}
CAMLprim value cipc_sem_ipc_set(value v_sem, value v_ds)
{
    CAMLparam2(v_sem, v_ds);
    struct semid_ds ds;
    Semid_val(v_ds, &ds);
    int rc = semctl(Sem_val(v_sem), 0, IPC_SET, &ds);
    if (rc == -1)
    {
        unix_error(errno, "semctl()", caml_copy_string("IPC_SET"));
    }
    CAMLreturn(Val_unit);
}
CAMLprim value cipc_sem_ipc_rmid(value v_sem)
{
    CAMLparam1(v_sem);
    int rc = semctl(Sem_val(v_sem), 0, IPC_RMID);
    if (rc == -1)
    {
        unix_error(errno, "semctl()", caml_copy_string("IPC_RMID"));
    }
    CAMLreturn(Val_unit);
}
CAMLprim value cipc_sem_ipc_info(value v_sem)
{
    CAMLparam1(v_sem);
    struct seminfo info;
    int rc = semctl(Sem_val(v_sem), 0, IPC_INFO, &info);
    if (rc == -1)
    {
        unix_error(errno, "semctl()", caml_copy_string("IPC_INFO"));
    }
    CAMLreturn(Val_seminfo(info));
}
CAMLprim value cipc_sem_info(value v_sem)
{
    CAMLparam1(v_sem);
    struct seminfo info;
    int rc = semctl(Sem_val(v_sem), 0, SEM_INFO, &info);
    if (rc == -1)
    {
        Semctl_error("SEM_INFO");
    }
    CAMLreturn(Val_seminfo(info));
}
CAMLprim value cipc_sem_getval(value v_sem, value v_semnum) 
{
    CAMLparam2(v_sem, v_semnum);
    int semval;
    int rc = semctl(Sem_val(v_sem), Int_val(v_semnum), GETVAL, &semval);
    if (rc == -1)
    {
        Semctl_error("GETVAL");
    }
    CAMLreturn(Val_int(rc));
}
CAMLprim value cipc_sem_setval(value v_sem, value v_semnum, value v_semval)
{
    CAMLparam3(v_sem, v_semnum, v_semval);
    int semval = Int_val(v_semval);
    int rc = semctl(Sem_val(v_sem), Int_val(v_semnum), SETVAL, semval);
    CAMLreturn(Val_unit);
}
CAMLprim value cipc_sem_get_all(value v_sem)
{
    CAMLparam1(v_sem);
    CAMLlocal1(v_ar);
    struct semid_ds ds;
    unsigned short int *un;
    int rc = semctl(Sem_val(v_sem), 0, SEM_STAT, &ds);
    if (rc == -1)
    {
        unix_error(errno, "semctl()", caml_copy_string("SEM_STAT"));
    }
    un = (unsigned short int *)malloc(ds.sem_nsems * sizeof(unsigned short int));
    rc = semctl(Sem_val(v_sem), 0, GETALL, un);
    if (rc == -1)
    {
        free(un);
        unix_error(errno, "semctl()", caml_copy_string("GETALL"));
    }
    v_ar = alloc_tuple(ds.sem_nsems);
    for (int i = 0; i < ds.sem_nsems; ++i)
    {
        Store_field(v_ar, i, Val_int(un[i]));
    }
    free(un);
    CAMLreturn(v_ar);
}
CAMLprim value cipc_sem_set_all(value v_sem, value v_semvals)
{
    CAMLparam2(v_sem, v_semvals);
    int nsems = caml_array_length(v_semvals);
    unsigned short int un[nsems];
    for (int i = 0; i < nsems; ++i)
    {
        un[i] = Int_val(Field(v_semvals, i));
    }
    int rc = semctl(Sem_val(v_sem), 0, SETALL, un);
    if (rc == -1)
    {
        unix_error(errno, "semctl()", caml_copy_string("SETALL"));
    }
    CAMLreturn(Val_unit);
}
CAMLprim value cipc_sem_get_pid(value v_sem)
{
    CAMLparam1(v_sem);
    int rc = semctl(Sem_val(v_sem), 0, GETPID, NULL);
    if (rc == -1)
    {
        unix_error(errno, "semctl()", caml_copy_string("GETPID"));
    }
    CAMLreturn(Val_int(rc));
}
CAMLprim value cipc_sem_get_ncnt(value v_sem, value v_semnum)
{
    CAMLparam2(v_sem, v_semnum);
    int rc = semctl(Sem_val(v_sem), Int_val(v_semnum), GETNCNT, NULL);
    if (rc == -1) 
    {
        Semctl_error("GETNCNT");
    }
    CAMLreturn(rc);
}
CAMLprim value cipc_sem_get_zcnt(value v_sem, value v_semnum)
{
    CAMLparam2(v_sem, v_semnum);
    int rc = semctl(Sem_val(v_sem), Int_val(v_semnum), GETZCNT, NULL);
    if (rc == -1)
    {
        Semctl_error("GETZCNT");
    }
    CAMLreturn(rc);
}
CAMLprim value cipc_semop(value v_sem, value v_sops)
{
    CAMLparam2(v_sem, v_sops);
    CAMLlocal1(v_str);
    int i;
    int len = caml_array_length(v_sops);
    struct sembuf sops[len];
    for (i = 0; i < len; ++i) {
        Sembuf_val(Field(v_sops, i), &sops[i]);
    }
    int rc = semop(Sem_val(v_sem), sops, len);
    if (rc == -1)
    {
        Semop_error("SEMOP");
    }
    CAMLreturn(Val_unit);
}

CAMLprim value cipc_sem_op1(value v_sem, value v_semnum, value v_semval, value v_flags)
{
    CAMLparam4(v_sem, v_semnum, v_semval, v_flags);
    struct sembuf sops[1];
    sops[0].sem_num = Int_val(v_semnum);
    sops[0].sem_op = Int_val(v_semval);
    sops[0].sem_flg = SemFlags_val(v_flags);
    int rc = semop(Sem_val(v_sem), sops, 1);
    if (rc == -1)
    {
        Semop_error("SEMOP1");
    }
    CAMLreturn(Val_unit);
}

CAMLprim value cipc_semtimedop(value v_sem, value v_sops, value v_timesp)
{
    CAMLparam3(v_sem, v_sops, v_timesp);
    struct timespec timeout;
    int i;
    int len = caml_array_length(v_sops);
    struct sembuf sops[len];
    Timespec_val(v_timesp, &timeout);
    for (int i = 0; i < len; ++i) {
        Sembuf_val(Field(v_sops, i), &sops[i]);
    }
    int rc = semtimedop(Sem_val(v_sem), sops, len, &timeout);
    if (rc == -1)
    {
        Semop_error("SEMTIMEDOP");
    }
    CAMLreturn(Val_unit);
}

CAMLprim value cipc_msgget(value v_key, value v_perms, value v_flags)
{
    CAMLparam3(v_key, v_perms, v_flags);
    int flags = Int_val(v_perms) | IpcFlags_val(v_flags);
    int rc = msgget(Key_val(v_key), flags);
    if (rc == -1)
    {
        unix_error(errno, "msgget()", caml_copy_string(""));
    }
    CAMLreturn(Val_msg(rc));
}
CAMLprim value cipc_msg_stat(value v_msg)
{
    CAMLparam1(v_msg);
    struct msqid_ds ds;
    int rc = msgctl(Msg_val(v_msg), MSG_STAT, &ds);
    if (rc == -1)
    {
        Msgctl_error("MSG_STAT");
    }
    CAMLreturn(Val_msqid(ds));
}
CAMLprim value cipc_msg_ipc_stat(value v_msg)
{
    CAMLparam1(v_msg);
    struct msqid_ds ds;
    int rc = msgctl(Msg_val(v_msg), IPC_STAT, &ds);
    if (rc == -1)
    {
        Msgctl_error("IPC_STAT");
    }
    CAMLreturn(Val_msqid(ds));
}
CAMLprim value cipc_msg_ipc_set(value v_msg, value v_ds)
{
    CAMLparam2(v_msg, v_ds);
    struct msqid_ds ds;
    Msqid_val(v_ds, &ds);
    int rc = msgctl(Msg_val(v_msg), IPC_SET, &ds);
    if (rc == -1)
    {
        Msgctl_error("IPC_SET");
    }
    CAMLreturn(Val_unit);
}
CAMLprim value cipc_msg_ipc_rmid(value v_msg)
{
    CAMLparam1(v_msg);
    int rc = msgctl(Msg_val(v_msg), IPC_RMID, NULL);
    if (rc == -1)
    {
        Msgctl_error("IPC_RMID");
    }
    CAMLreturn(Val_unit);
}
CAMLprim value cipc_msg_ipc_info(value v_msg)
{
    CAMLparam1(v_msg);
    struct msginfo info;
    int rc = msgctl(Msg_val(v_msg), IPC_INFO, (struct msqid_ds *)&info);
    if (rc == -1)
    {
        Msgctl_error("IPC_INFO");
    }
    CAMLreturn(Val_msginfo(info));
}
CAMLprim value cipc_msg_info(value v_msg)
{
    CAMLparam1(v_msg);
    struct msginfo info;
    int rc = msgctl(Msg_val(v_msg), MSG_INFO, (struct msqid_ds *)&info);
    if (rc == -1)
    {
        Msgctl_error("MSG_INFO");
    }
    CAMLreturn(Val_msginfo(info));
}

struct cipc_msg {
    long mtype;
    char mtext[1];
};

CAMLprim value cipc_msg_send(value v_mid, value v_msg, value v_flgs)
{
    CAMLparam3(v_mid, v_msg, v_flgs);
    CAMLlocal2(v_mtype, v_mtext);
    struct cipc_msg *msg;

    v_mtype = Field(v_msg, 0);
    v_mtext = Field(v_msg, 1);
    int mlen = caml_string_length(v_mtext);
    int blen = mlen * sizeof(char);
    char buf[blen];
    msg = (struct cipc_msg *)buf;
    msg->mtype = Long_val(v_mtype);
    memcpy(msg->mtext, String_val(v_mtext), blen);
    int rc = msgsnd(Msg_val(v_mid), (const void *)msg, mlen, MsgFlags_val(v_flgs));
    if (rc == -1)
    {
        unix_error(errno, "msgsnd()", caml_copy_string(""));
    }
    CAMLreturn(Val_unit);
}
CAMLprim value cipc_msg_recv(value v_mid, value v_mtype, value v_sz, value v_flgs)
{
    CAMLparam4(v_mid, v_mtype, v_sz, v_flgs);
    CAMLlocal2(v_msg, v_mtext);
    struct cipc_msg *msg;
    int mlen = Int_val(v_sz);
    int mflgs = MsgFlags_val(v_flgs);
    char mtext[mlen + sizeof(long)];
    msg = (struct cipc_msg *)mtext;

    int rc = msgrcv(Msg_val(v_mid), (void *)msg, mlen, Int_val(v_mtype), mflgs);
    if (rc == -1)
    {
        unix_error(errno, "msgrcv()", caml_copy_string(""));
    }
    /* Copy the string */
    v_mtext = caml_alloc_string(rc);
    memcpy((char *)String_val(v_mtext), msg->mtext, rc);

    v_msg = alloc_tuple(2);
    Store_field(v_msg, 0, Val_int(msg->mtype));
    Store_field(v_msg, 1, v_mtext);
    CAMLreturn(v_msg);
}

CAMLprim value cipc_shmget(value v_key, value v_sz, value v_perms, value v_flgs)
{
    CAMLparam4(v_key, v_sz, v_perms, v_flgs);
    int shm = shmget(Key_val(v_key), Int_val(v_sz), Int_val(v_perms) | ShmgetFlags_val(v_flgs));
    if (shm == -1)
    {
        unix_error(errno, "shmget()", caml_copy_string(""));
    }
    CAMLreturn(Val_shm(shm));
}

CAMLprim value cipc_shm_ipc_stat(value v_shm)
{
    CAMLparam1(v_shm);
    struct shmid_ds ds;
    int rc = shmctl(Shm_val(v_shm), IPC_STAT, &ds);
    if (rc == -1)
    {
        Shmctl_error("IPC_STAT");
    }
    CAMLreturn(Val_shmid(ds));
}
CAMLprim value cipc_shm_ipc_set(value v_shm, value v_ds)
{
    CAMLparam2(v_shm, v_ds);
    struct shmid_ds ds;
    Shmid_val(v_ds, &ds);
    int rc = shmctl(Shm_val(v_shm), IPC_SET, &ds);
    if (rc == -1)
    {
        Shmctl_error("IPC_SET");
    }
    CAMLreturn(Val_unit);
}
CAMLprim value cipc_shm_ipc_rmid(value v_shm) 
{
    CAMLparam1(v_shm);
    int rc = shmctl(Shm_val(v_shm), IPC_RMID, NULL);
    if (rc == -1)
    {
        Shmctl_error("IPC_RMID");
    }
    CAMLreturn(Val_unit);
}
CAMLprim value cipc_shm_ipc_info(value v_shm)
{
    CAMLparam1(v_shm);
    struct shminfo info;
    int rc = shmctl(Shm_val(v_shm), IPC_INFO, (struct shmid_ds *)&info);
    if (rc == -1)
    {
        Shmctl_error("IPC_INFO");
    }
    CAMLreturn(Val_shminfo(info));
}
CAMLprim value cipc_shm_info(value v_shm)
{
    CAMLparam1(v_shm);
    struct shm_info info;
    int rc = shmctl(Shm_val(v_shm), SHM_INFO, (struct shmid_ds *)&info);
    if (rc == -1)
    {
        Shmctl_error("SHM_INFO");
    }
    CAMLreturn(Val_shm_info(info));
}
CAMLprim value cipc_shm_stat(value v_shm)
{
    CAMLparam1(v_shm);
    struct shmid_ds ds;
    int rc = shmctl(Shm_val(v_shm), SHM_STAT, &ds);
    if (rc == -1)
    {
        Shmctl_error("SHM_STAT");
    }
    CAMLreturn(Val_shmid(ds));
}
CAMLprim value cipc_shm_lock(value v_shm)
{
    CAMLparam1(v_shm);
    int rc = shmctl(Shm_val(v_shm), SHM_LOCK, NULL);
    if (rc == -1)
    {
        Shmctl_error("SHM_LOCK");
    }
    CAMLreturn(Val_unit);
}
CAMLprim value cipc_shm_unlock(value v_shm)
{
    CAMLparam1(v_shm);
    int rc = shmctl(Shm_val(v_shm), SHM_UNLOCK, NULL);
    if (rc == -1)
    {
        Shmctl_error("SHM_UNLOCK");
    }
    CAMLreturn(Val_unit);
}
CAMLprim value cipc_shm_attach(value v_shm, value v_flgs)
{
    CAMLparam2(v_shm, v_flgs);
    void *addr;

    addr = shmat(Shm_val(v_shm), NULL, ShmFlags_val(v_flgs));
    if ((long)addr == -1)
    {
        unix_error(errno, "shmat()", caml_copy_string(""));
    }
    CAMLreturn(Val_addr(addr)); 
}
CAMLprim value cipc_shm_detach(value v_addr)
{
    CAMLparam1(v_addr);
    int rc = shmdt(Addr_val(v_addr));
    if (rc == -1)
    {
        unix_error(errno, "shmdt()", caml_copy_string(""));
    }
    CAMLreturn(Val_unit);
}

CAMLprim value cipc_shm_addr_get_bytes(value v_addr, value v_len)
{
    CAMLparam2(v_addr, v_len);
    CAMLlocal1(v_str);
    char *addr = Addr_val(v_addr);
    int len = Int_val(v_len);
    char *str;

    v_str = caml_alloc_string(len);
    str = (char *)String_val(v_str);
    for (int idx = 0; idx < len; ++idx)
    {
        str[idx] = addr[idx];
    }
    CAMLreturn(v_str);
}
CAMLprim value cipc_shm_addr_sub(value v_addr, value v_ofs, value v_len)
{
    CAMLparam3(v_addr, v_ofs, v_len);
    CAMLlocal1(v_str);
    int ofs = Int_val(v_ofs);
    int len = Int_val(v_len);
    char *addr = (char *)Addr_val(v_addr);
    char *str;
    v_str = caml_alloc_string(Int_val(v_len));
    str = (char *)String_val(v_str);
    for (int idx = 0; idx < len; ++idx) 
    {
        str[idx] = addr[ofs+idx];
    }
    CAMLreturn(v_str);
}
CAMLprim value cipc_shm_addr_get_ch(value v_addr, value v_idx)
{
    CAMLparam2(v_addr, v_idx);
    char *addr = Addr_val(v_addr);
    CAMLreturn(Val_int(addr[Int_val(v_idx)]));
}
CAMLprim value cipc_shm_addr_set_ch(value v_addr, value v_idx, value v_ch)
{
    CAMLparam3(v_addr, v_idx, v_ch);
    char *addr = Addr_val(v_addr);
    addr[Int_val(v_idx)] = (char)Int_val(v_ch);
    CAMLreturn(Val_unit);
}
CAMLprim value cipc_shm_addr_add_bytes(value v_addr, value v_ofs, value v_str)
{
    CAMLparam3(v_addr, v_ofs, v_str);
    char *addr = (char *)Addr_val(v_addr);
    char *str = (char *)String_val(v_str);
    int ofs = Int_val(v_ofs);
    int len = caml_string_length(v_str);
    for (int idx = 0; idx < len; ++idx) 
    {
        addr[ofs + idx] = str[idx];
    }
    CAMLreturn(Val_unit);
}
CAMLprim value cipc_shm_addr_clear(value v_addr, value v_ofs, value v_len, value v_chr)
{
    CAMLparam4(v_addr, v_ofs, v_len, v_chr);
    char *addr = (char *)Addr_val(v_addr);
    int ofs = Int_val(v_ofs);
    int len = Int_val(v_len);
    char chr = (char)Int_val(v_chr);
    for (int idx = 0; idx < len; ++idx) {
        addr[ofs+idx] = chr;
    }
    CAMLreturn(Val_unit);
}
CAMLprim value cipc_shm_addr_indexp(value v_addr, value v_len, value v_ofs, value v_ch)
{
    CAMLparam4(v_addr, v_len, v_ofs, v_ch);
    char *addr = Addr_val(v_addr);
    int len = Int_val(v_len);
    char ch = Int_val(v_ch);
    int pos = Int_val(v_ofs);
    while (pos < len && addr[pos] != ch) {
        pos = pos + 1;
    }
    pos = (pos >= len) ? -1 : pos;
    CAMLreturn(Val_int(pos));
}
