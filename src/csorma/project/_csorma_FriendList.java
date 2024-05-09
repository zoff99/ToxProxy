
@Table
public class FriendList
{
    @PrimaryKey
    public String tox_public_key_string = "";

    @Column
    @Nullable
    public String name;

    @Column
    @Nullable
    public String alias_name;

@Column
public int friendlist_id;

          @Column
                 @Nullable
                         public String status_message;


@Column
public long message_id;

    @Column
    public boolean read = false;
                        
    @Column
    public int TOX_CONNECTION; // 0 --> NONE (offline), 1 --> TCP (online), 2 --> UDP (online)

    @Column
    public int TOX_CONNECTION_real; // 0 --> NONE (offline), 1 --> TCP (online), 2 --> UDP (online)

    @Column
    public int TOX_CONNECTION_on_off; // 0 --> offline, 1 --> online

    @Column
    public int TOX_CONNECTION_on_off_real; // 0 --> offline, 1 --> online

    @Column
    public int TOX_USER_STATUS; // 0 --> NONE, 1 --> online AWAY, 2 --> online BUSY

    @Column
    @Nullable
    public String avatar_pathname;

    @Column
    @Nullable
    public String avatar_filename;

    @Column
    @Nullable
    public String avatar_hex;

    @Column
    @Nullable
    public String avatar_hash_hex;

    @Column
    @Nullable
    public boolean avatar_update = false; // has avatar changed for this friend?

    // ______@@SORMA_END@@______

comments and information go here.
what ever you want.

the generator will ignore it down here.

