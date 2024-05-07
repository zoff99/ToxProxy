@Table
public class group_message
{
    @PrimaryKey(autoincrement = true)
    public long id; // uniqe message id!!

    @Column
    public String groupid;
    @Column
    public String peerpubkey;
    @Column
    public String datahex;
    @Column
    public int message_id;

    @Column
    public int timstamp_recv;

    @Column
    public int mtype;
}
