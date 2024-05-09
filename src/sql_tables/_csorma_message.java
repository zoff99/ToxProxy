@Table
public class message
{
    @PrimaryKey(autoincrement = true)
    public long id; // uniqe message id!!

    @Column
    public String pubkey;

    @Column
    public String datahex;

    @Column
    public String wrappeddatahex;

    @Column
    public int message_id;

    @Column
    public int timstamp_recv;

    @Column
    public String message_hashid;

    @Column
    public String message_sync_hashid;

    @Column
    public int mtype;


}
