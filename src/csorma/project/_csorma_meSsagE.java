
@Table
public class meSsagE
{
    @PrimaryKey(autoincrement = true, auto = true)
    public long id; // uniqe message id!!

    @Column
    public long message_id = -1; // ID given from toxcore!!

    @Column
    public String tox_friendpubkey;

    @Column
    public int direction = 0; // 0 -> msg received, 1 -> msg sent

    @Column
    public int TOX_MESSAGE_TYPE = 0; // 0 -> normal, 1 -> action

    @Column
    public int TRIFA_MESSAGE_TYPE = TRIFA_MSG_TYPE_TEXT.value;

    @Column
    public int state = TOX_FILE_CONTROL_PAUSE.value;

    @Column
    public boolean ft_accepted = false;

    @Column
    public boolean ft_outgoing_started = false;

    @Column
    public long filedb_id; // f_key -> FileDB.id

    @Column
    public long filetransfer_id; // f_key -> Filetransfer.id

    @Column
    @Nullable
    public long sent_timestamp = 0L;

    @Column
    @Nullable
    public long sent_timestamp_ms = 0L;

    @Column
    @Nullable
    public long rcvd_timestamp = 0L;

    @Column
    @Nullable
    public long rcvd_timestamp_ms = 0L;

    @Column
    public boolean read = false;

    @Column
    public int send_retries = 0;

    @Column
    public boolean is_new = true;

    @Column(indexed = true, helpers = Column.Helpers.ALL)
    @Nullable
    public String text = null;

    @Column(helpers = Column.Helpers.ALL)
    @Nullable
    public String filename_fullpath = null;

    @Column(indexed = true, helpers = Column.Helpers.ALL)
    @Nullable
    public String msg_id_hash = null; // 32byte hash, used for MessageV2 Messages! and otherwise NULL

    @Column(indexed = true, helpers = Column.Helpers.ALL)
    @Nullable
    public String raw_msgv2_bytes = null; // used for MessageV2 Messages! and otherwise NULL

    @Column(indexed = true, defaultExpr = "0")
    public int msg_version; // 0 -> old Message, 1 -> for MessageV2 Message

    @Column(indexed = true, defaultExpr = "2")
    public int resend_count; // for msgV2 "> 1" -> do not resend msg anymore, 0 or 1 -> resend count

    @Column(indexed = true, defaultExpr = "false", helpers = Column.Helpers.ALL)
    public boolean ft_outgoing_queued = false;

    @Column(indexed = true, defaultExpr = "false", helpers = Column.Helpers.ALL)
    public boolean msg_at_relay = false;

    @Column(indexed = true, helpers = Column.Helpers.ALL)
    @Nullable
    public String msg_idv3_hash = null; // 32byte hash, used for MessageV3 Messages! and otherwise NULL

    @Column(helpers = Column.Helpers.ALL)
    @Nullable
    public int sent_push = 0;

    @Column(helpers = Column.Helpers.ALL, defaultExpr = "0")
    @Nullable
    public int filetransfer_kind = TOX_FILE_KIND_DATA.value;

