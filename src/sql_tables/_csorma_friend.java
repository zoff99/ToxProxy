@Table
public class friend
{
    @PrimaryKey
    public String pubkey;
    @Column
    public boolean is_master;
    @Column
    public boolean is_silent;
}
