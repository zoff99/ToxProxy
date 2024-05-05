@Table
public class friend
{
    @PrimaryKey(autoincrement = true)
    public long id; // uniqe message id!!
    @Column
    public String pubkey;
    @Column
    public boolean is_master;
}
