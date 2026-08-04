@Table
public class group
{
    @PrimaryKey
    public String groupid;
    @Column
    public boolean is_silent;
    @Column
    long last_update_timestamp = -1L;
    @Column
    int missed_sync_count = 0;
    @Column
    int sync_seen = 0;
}
