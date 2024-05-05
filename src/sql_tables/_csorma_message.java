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
    public int mtype;
    @Column
    public boolean isgroupmsg;
}
