@Table
public class group
{
    @PrimaryKey(autoincrement = true)
    public long id; // uniqe message id!!
    @Column
    public String groupid;
    @Column
    public boolean is_silent;
}
