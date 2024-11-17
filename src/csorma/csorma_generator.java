import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.stream.Stream;

public class csorma_generator {
    private static final String TAG = "Generator";
    static final String Version = "0.99.3";
    static final String out_dir = "gen/";
    static final String prefix = "_csorma_";
    static final String in_suffix = ".java";
    static final String proto_dir = "./template/";
    static final String runtime_header = "csorma_runtime.h";
    static final String runtime_header_in = "_csorma_runtime.h";
    static final String runtime_header_table_in = "_csorma_runtime_table.h";
    static final String makefile = "Makefile";
    static final String sqlite_src_dir = "sqlite/";
    static final String sqlcipher_src_dir = "sqlcipher/";
    static final String makefile_in = "_Makefile";
    static final String tbl_h_proto = "_table.h";
    static final String tbl_c_proto = "_table.c";
    static final String tbl_stub_1 = "_csorma_stub1.c";
    static final String tbl_stub_2 = "_csorma_stub2.c";
    static final String tbl_stub_out = "csorma_stub.c";
    static final String tbl_fc_ext = ".c";
    static final String tbl_fh_ext = ".h";
    static final String tbl_s_ext = ".sql";
    static final String tbl_cs_ext = ".txt";

    static String mkf_tables_o_list = "";
    static String mkf_tables_o_compile = "";

    static String tbl_tostring = "";
    static String tbl_tolist = "";
    static int column_num = 0;
    static String primary_key_column_name = "";
    static boolean primary_key_column_autoincr_if_needed = false;
    static String primary_key_column_autoincr_if_needed_str = " AUTOINCREMENT";
    static String primary_key_column_sqlitetype = "";
    static String tbl_insert = "";
    static String tbl_insert_sub01 = "";
    static String tbl_insert_sub02 = "";
    static String tbl_insert_sub03 = "";
    static String tbl_equalfuncs = "";
    static String tbl_columns_for_struct_01 = "";


    static String tbl_col_setters = "";
    static String tbl_inserters = "";
    static String tbl_inserters_a = "";
    static String tbl_inserters_b = "";
    static String tbl_inserters_c = "";
    static String tbl_inserter_bind = "";
    static String tbl_equalfuncs_3 = "";
    static String tbl_setfuncs_3 = "";
    static String tbl_equalfuncs_2 = "";
    static String tbl_setfuncs_2 = "";
    static String tbl_freefuncs_1 = "";

    static String tbl_runtime_incl_1 = "";
    static String tbl_runtime_incl_all = "";

    static String tbl_orderbyfuncs = "";
    static String tbl_setfuncs = "";

    enum COLTYPE
    {
        INT(1), LONG(2), STRING(3), BOOLEAN(4), UNKNOWN(999);
        private int value;
        private String name;
        private String ctype;
        private String sqlitetype;
        private String csqlitetype;
        private String bcsqlitetype;
        private COLTYPE(int value)
        {
            this.value = value;
            if (value == 1) { this.name = "INT"; };
            if (value == 2) { this.name = "LONG"; };
            if (value == 3) { this.name = "STRING"; };
            if (value == 4) { this.name = "BOOLEAN"; };
            if (value == 999) { this.name = "UNKNOWN"; };
            if (value == 1) { this.ctype = "int32_t"; };
            if (value == 2) { this.ctype = "int64_t"; };
            if (value == 3) { this.ctype = "csorma_s *"; };
            if (value == 4) { this.ctype = "bool"; };
            if (value == 999) { this.ctype = "void *"; };
            if (value == 1) { this.csqlitetype = "Int"; };
            if (value == 2) { this.csqlitetype = "Long"; };
            if (value == 3) { this.csqlitetype = "String"; };
            if (value == 4) { this.csqlitetype = "Boolean"; };
            if (value == 999) { this.csqlitetype = "String"; };
            if (value == 1) { this.bcsqlitetype = "int"; };
            if (value == 2) { this.bcsqlitetype = "int"; };
            if (value == 3) { this.bcsqlitetype = "string"; };
            if (value == 4) { this.bcsqlitetype = "int"; };
            if (value == 999) { this.bcsqlitetype = "string"; };
            if (value == 1) { this.sqlitetype = "INTEGER"; };
            if (value == 2) { this.sqlitetype = "INTEGER"; };
            if (value == 3) { this.sqlitetype = "TEXT"; };
            if (value == 4) { this.sqlitetype = "BOOLEAN"; };
            if (value == 999) { this.sqlitetype = "TEXT"; };
        }
    }

    public static String cap_first(final String in)
    {
        if (in.length() < 1)
        {
            return in;
        }

        if (in.length() == 1)
        {
            return in.substring(0, 1).toUpperCase();
        }
        else
        {
            return in.substring(0, 1).toUpperCase() + in.substring(1).toLowerCase();
        }
    }

    public static String lc(final String in)
    {
        if (in.length() < 1)
        {
            return in;
        }

        return in.toLowerCase();
    }

    public static void main(String[] args) {
        System.out.println("Generator v" + Version);
        System.out.println("checking directory: " + args[0]);

        try
        {
            final String workdir = args[0];
            begin_csorma(workdir);

            for (final File fileEntry : new File(workdir).listFiles()) {
                if (!fileEntry.isDirectory()) {
                    if (fileEntry.getName().startsWith(prefix))
                    {
                        System.out.println(fileEntry.getName());
                        generate_table(workdir, fileEntry.getName());
                    }
                }
            }

            finish_csorma(workdir);

            String[] list = new String[]{"csorma.c","csorma.h","logger.c","logger.h","csorma_example.c","csorma_test.c"};
            for (String i : list)
            {
                System.out.println("copying File: " + i);
                copy_file(new File(proto_dir + File.separator + i), new File(workdir + File.separator + out_dir + File.separator + i));
            }

            File d = new File(workdir + File.separator + out_dir + File.separator + sqlite_src_dir);
            d.mkdirs();

            String[] list2 = new String[]{"sqlite3.c","sqlite3.h"};
            for (String i2 : list2)
            {
                System.out.println("copying File: " + sqlite_src_dir + File.separator + i2);
                copy_file(new File(sqlite_src_dir + File.separator + i2),
                    new File(workdir + File.separator + out_dir + File.separator + sqlite_src_dir + File.separator + i2));
            }


            File d5 = new File(workdir + File.separator + out_dir + File.separator + sqlcipher_src_dir);
            d5.mkdirs();

            String[] list5 = new String[]{"sqlite3.c","sqlite3.h"};
            for (String i2 : list5)
            {
                System.out.println("copying File: " + sqlcipher_src_dir + File.separator + i2);
                copy_file(new File(sqlcipher_src_dir + File.separator + i2),
                    new File(workdir + File.separator + out_dir + File.separator + sqlcipher_src_dir + File.separator + i2));
            }

            String[] list3 = new String[]{"invalid_UTF-8-test.dat","UTF-8-demo.html"};
            for (String i3 : list3)
            {
                System.out.println("copying File: " + i3);
                copy_file(new File(i3),
                    new File(workdir + File.separator + out_dir + File.separator + i3));
            }
        }
        catch(Exception e)
        {
            e.printStackTrace();
        }
    }

    private static void copy_file(File sourceFile, File destFile)
    {
        if (!sourceFile.exists())
        {
            return;
        }
        try
        {
            Files.copy(sourceFile.toPath(), destFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
        }
        catch(Exception e)
        {
            e.printStackTrace();
        }
    }

    static void begin_csorma(final String workdir)
    {
        System.out.println("starting: " + workdir + File.separator + out_dir + runtime_header);
        tbl_runtime_incl_all = "";

        try
        {
            File d = new File(workdir + File.separator + out_dir);
            d.mkdirs();
            final String o1 = read_text_file(proto_dir + File.separator  + tbl_stub_1);
            FileWriter fstream = new FileWriter(workdir + File.separator + out_dir + tbl_stub_out,
                StandardCharsets.UTF_8);
            BufferedWriter out = new BufferedWriter(fstream);
            out.write(o1);
            out.newLine();
            out.close();
        }
        catch(Exception e)
        {
            e.printStackTrace();
        }
    }

    static void finish_csorma(final String workdir)
    {
        System.out.println("finishing: " + workdir + File.separator + out_dir + runtime_header);
        try
        {
            File d = new File(workdir + File.separator + out_dir);
            d.mkdirs();
            final String o1 = read_text_file(proto_dir + File.separator  + runtime_header_in);
            FileWriter fstream = new FileWriter(workdir + File.separator + out_dir + runtime_header,
                StandardCharsets.UTF_8);
            BufferedWriter out = new BufferedWriter(fstream);
            out.write(o1.replace("__@@@TABLES_RUNTIME_01@@@__", tbl_runtime_incl_all));
            out.newLine();
            out.close();
        }
        catch(Exception e)
        {
            e.printStackTrace();
        }

        System.out.println("finishing: " + workdir + File.separator + out_dir + makefile);
        try
        {
            File d = new File(workdir + File.separator + out_dir);
            d.mkdirs();
            final String o1 = read_text_file(proto_dir + File.separator  + makefile_in);
            FileWriter fstream = new FileWriter(workdir + File.separator + out_dir + makefile,
                StandardCharsets.UTF_8);
            BufferedWriter out = new BufferedWriter(fstream);
            out.write(o1.replace("__@@@TABLES_O_FILES@@@__", mkf_tables_o_list)
                        .replace("__@@@TABLES_COMPILE_O_FILES@@@__", mkf_tables_o_compile));
            out.newLine();
            out.close();
        }
        catch(Exception e)
        {
            e.printStackTrace();
        }

        try
        {
            File d = new File(workdir + File.separator + out_dir);
            d.mkdirs();
            final String o1 = read_text_file(proto_dir + File.separator  + tbl_stub_2);
            FileWriter fstream = new FileWriter(workdir + File.separator + out_dir + tbl_stub_out,
                StandardCharsets.UTF_8, true);
            BufferedWriter out = new BufferedWriter(fstream);
            out.write(o1);
            out.newLine();
            out.close();
        }
        catch(Exception e)
        {
            e.printStackTrace();
        }
    }

    static void generate_table(final String workdir, final String infilename)
    {
        String table_name = "";
        primary_key_column_name = "";
        primary_key_column_autoincr_if_needed = false;
        primary_key_column_autoincr_if_needed_str = "";
        primary_key_column_sqlitetype = "";
        BufferedReader reader;
		try {
			reader = new BufferedReader(new FileReader(workdir + File.separator + infilename));
			String line = reader.readLine();

            boolean ignore_line = true;
			while (line != null) {
                // System.out.println("LLLLLLL: " + line.trim());
                if (line.trim().contains("@Table"))
                {
                    ignore_line = false;
                    line = reader.readLine();
                    while(line.trim().startsWith("@"))
                    {
                        line = reader.readLine();
                    }
                    table_name = line.trim().substring(line.trim().lastIndexOf(" ") + 1);
                    table_name = cap_first(table_name);
                    System.out.println("Table: " + table_name);
                    process_tablename(workdir, table_name);
                }
                else if (ignore_line)
                {
                    line = reader.readLine();
                    continue;
                }
                else if (line.contains("______@@SORMA_END@@______"))
                {
                    break;
                }
                else if (line.trim().contains("@PrimaryKey"))
                {
                    String primary_key_line = line.trim();
                    line = reader.readLine();
                    while(line.trim().startsWith("@"))
                    {
                        line = reader.readLine();
                    }
                    // System.out.println("PrimaryKey: " + line.trim());
                    primary_key_column_name = process_primary_key(workdir, infilename, table_name, line.trim(), primary_key_line);
                }
                else if (line.trim().contains("@Column"))
                {
                    line = reader.readLine();
                    while(line.trim().startsWith("@"))
                    {
                        line = reader.readLine();
                    }
                    // System.out.println("Column: " + line.trim());
                    process_column(workdir, infilename, line.trim(), table_name);
                }
				// System.out.println(line);
				line = reader.readLine();
			}

			reader.close();

            finish_table(workdir, table_name);

		} catch (Exception e) {
			e.printStackTrace();
		}
    }

    static String process_primary_key(final String workdir, final String infilename,
                                    final String table_name,
                                    final String p,
                                    final String primary_key_line)
    {
        final String p2 = remove_public(p);
        final String p3 = remove_type(p2);
        final String column_name = get_name(p3).toLowerCase();
        final COLTYPE p5 = get_type(p2);

        primary_key_column_autoincr_if_needed = false;
        primary_key_column_autoincr_if_needed_str = "";
        primary_key_column_sqlitetype = p5.sqlitetype;
        if (p5 == COLTYPE.LONG)
        {
            // autoincrement = true
            if (primary_key_line.toLowerCase().contains("autoincrement = true"))
            {
                System.out.println("P: "+ "AUTOINCREMENT");
                primary_key_column_autoincr_if_needed = true;
                primary_key_column_autoincr_if_needed_str = " AUTOINCREMENT";
            }
        }

        System.out.println("P: " + column_name + " type: " + p5.name);

        append_to_sql(workdir, table_name, "  \""+column_name+"\" "+primary_key_column_sqlitetype+",");

        if (!primary_key_column_autoincr_if_needed)
        {
            column_num++;
            add_col_inserters(table_name, column_name, p5, p5.ctype, column_num);
            add_col_inserter_bind(table_name, column_name, p5, p5.ctype, column_num);
        }

        add_col_setters_func(table_name, column_name, p5, p5.ctype);
        add_equal_func02(table_name, column_name, p5, p5.ctype);
        add_set_func02(table_name, column_name, p5, p5.ctype);
        add_equal_func03(table_name, column_name, p5, p5.ctype);
        add_set_func03(table_name, column_name, p5, p5.ctype);
        add_free_func01(table_name, column_name, p5, p5.ctype);

        tbl_columns_for_struct_01 += "    " + p5.ctype + " "  + column_name + ";\n";

        add_equal_func(table_name, column_name, p5, p5.ctype);
        add_orderby_func(table_name, column_name, p5, p5.ctype);
        add_set_func(table_name, column_name, p5, p5.ctype);

        return(column_name);
    }

    static void process_column(final String workdir, final String infilename, final String c, final String table_name)
    {
        final String c2 = remove_public(c);
        final String c3 = remove_type(c2);
        final String column_name = get_name(c3).toLowerCase();
        final COLTYPE c5 = get_type(c2);
        System.out.println("C: " + column_name + " type: " + c5.name);

        append_to_sql(workdir, table_name, "  \""+column_name+"\" "+c5.sqlitetype+",");

        column_num++;

        add_col_inserters(table_name, column_name, c5, c5.ctype, column_num);
        add_col_inserter_bind(table_name, column_name, c5, c5.ctype, column_num);

        add_col_setters_func(table_name, column_name, c5, c5.ctype);
        add_equal_func02(table_name, column_name, c5, c5.ctype);
        add_set_func02(table_name, column_name, c5, c5.ctype);
        add_equal_func03(table_name, column_name, c5, c5.ctype);
        add_set_func03(table_name, column_name, c5, c5.ctype);
        add_free_func01(table_name, column_name, c5, c5.ctype);

        tbl_columns_for_struct_01 += "    " + c5.ctype + " "  + column_name + ";\n";

        add_equal_func(table_name, column_name, c5, c5.ctype);
        add_orderby_func(table_name, column_name, c5, c5.ctype);
        add_set_func(table_name, column_name, c5, c5.ctype);
    }

    static String r_(final String in, final String tablename, final String column_name, COLTYPE ctype)
    {
        String _const_ = "const";
        if (ctype == COLTYPE.STRING)
        {
            _const_ = "";
        }
        return in.replace("__@@@TABLE@@@__", tablename)
                .replace("__@@@TABLEuc@@@__", tablename.toUpperCase())
                .replace("__@@@TABLElc@@@__", tablename.toLowerCase())
                .replace("__@@@COLUMN_NAME@@@__", column_name.toLowerCase())
                .replace("__@@@CTYPE_CTYPE@@@__", ctype.ctype)
                .replace("__@@@CTYPE_CSTYPE@@@__", ctype.csqlitetype)
                .replace("__@@@CTYPE_BCSTYPE@@@__", ctype.bcsqlitetype)
                .replace("__@@@CTYPE_CONST_CTYPE@@@__", _const_)
                ;
    }

    static void add_free_func01(final String table_name, final String column_name, final COLTYPE ctype,
                final String ctype_firstupper)
    {
        if (ctype == COLTYPE.STRING)
        {
            tbl_freefuncs_1 += "    " + "csorma_str_free(t->" + lc(column_name) + ");";
            tbl_freefuncs_1  += "" + "\n";
        }
    }

    static void add_col_inserter_bind(final String table_name, final String column_name, final COLTYPE ctype,
                final String ctype_firstupper, final int column_num)
    {
        if (ctype == COLTYPE.LONG)
        {
            tbl_inserter_bind  += "        " + "bindvar_to_stmt(res, " + column_num + ", BINDVAR_TYPE_" + ctype.csqlitetype +
                ", _BIND_NaN, t->" + lc(column_name) + ", _BIND_NaN);";
        }
        else if ((ctype == COLTYPE.INT)||(ctype == COLTYPE.BOOLEAN))
        {
            tbl_inserter_bind  += "        " + "bindvar_to_stmt(res, " + column_num + ", BINDVAR_TYPE_" + ctype.csqlitetype +
                ", t->" + lc(column_name) + ", _BIND_NaN, _BIND_NaN);";
        }
        else if (ctype == COLTYPE.STRING)
        {
            tbl_inserter_bind  += "        " + "bindvar_to_stmt(res, " + column_num + ", BINDVAR_TYPE_" + ctype.csqlitetype +
                ", _BIND_NaN, _BIND_NaN, t->" + lc(column_name) + ");";
        }

        tbl_inserter_bind  += "" + "\n";
    }

    static void add_col_inserters(final String table_name, final String column_name, final COLTYPE ctype,
                final String ctype_firstupper, final int column_num)
    {
        if (column_num == 1)
        {
            tbl_inserters_a  += "    char *sql1 = \"(\"\n";
            tbl_inserters_a  += "                \"";
        }
        else
        {
            tbl_inserters_a  += "                \",";
        }
        tbl_inserters_a  += "" + "\\\""+lc(column_name)+"\\\""+ "\"\n";


        if (column_num == 1)
        {
            tbl_inserters_b  += "                \")\"\n";
            tbl_inserters_b  += "                \" values \"\n";
            tbl_inserters_b  += "                \"(\"\n";
            tbl_inserters_b  += "                \"?";
        }
        else
        {
            tbl_inserters_b  += "                \",?";
        }
        tbl_inserters_b  += "" +column_num+ "\"\n";


        if (column_num == 1)
        {
            tbl_inserters_c  += "                \")\"\n";
            tbl_inserters_c  += "                ;\n";
        }
    }

    static void add_col_setters_func(final String table_name, final String column_name, final COLTYPE ctype, final String ctype_firstupper)
    {
        if ((ctype == COLTYPE.INT)||(ctype == COLTYPE.LONG))
        {
            tbl_col_setters  += "            " + "tx->" + lc(column_name) + " = __rs_get" + ctype.csqlitetype +
                "(res, \"" + lc(column_name) + "\");";
        }
        else if (ctype == COLTYPE.BOOLEAN)
        {
            tbl_col_setters  += "            " + "tx->" + lc(column_name) + " = __rs_get" + ctype.csqlitetype +
                "(res, \"" + lc(column_name) + "\");";
        }
        else if (ctype == COLTYPE.STRING)
        {
            tbl_col_setters  += "            " + "tx->" + lc(column_name) + " = __rs_get" + ctype.csqlitetype +
                "(res, \"" + lc(column_name) + "\");";
        }

        tbl_col_setters  += "" + "\n";
    }

    static void process_tablename(final String workdir, final String tablename)
    {
        System.out.println("appending to csorma: " + workdir + File.separator + out_dir); // + outfilename);
        begin_table(workdir, tablename);
    }

    static void begin_table(final String workdir, final String tablename)
    {
        System.out.println("starting: " + workdir + File.separator + out_dir + tablename + tbl_s_ext);
        tbl_insert_sub01 = "";
        tbl_insert_sub02 = "";
        tbl_insert_sub03 = "";
        tbl_columns_for_struct_01 = "";
        tbl_equalfuncs =   "";
        tbl_orderbyfuncs = "";
        tbl_setfuncs =     "";

        tbl_col_setters = "";
        tbl_inserters = "";
        tbl_inserters_a = "";
        tbl_inserters_b = "";
        tbl_inserters_c = "";
        tbl_inserter_bind = "";
        tbl_equalfuncs_3 = "";
        tbl_setfuncs_3 = "";
        tbl_equalfuncs_2 = "";
        tbl_setfuncs_2 = "";
        tbl_freefuncs_1 = "";

        column_num = 0;

        final String outstr = "CREATE TABLE IF NOT EXISTS \""+tablename+"\" (";

        try
        {
            File d = new File(workdir + File.separator + out_dir);
            d.mkdirs();
            FileWriter fstream = new FileWriter(workdir + File.separator + out_dir + tablename + tbl_s_ext,
                StandardCharsets.UTF_8);
            BufferedWriter out = new BufferedWriter(fstream);
            out.write(outstr);
            out.newLine();
            out.close();

            fstream = new FileWriter(workdir + File.separator + out_dir + tablename + tbl_cs_ext,
                StandardCharsets.UTF_8);
            out = new BufferedWriter(fstream);
            out.write("{");
            out.newLine();
            out.write("char *sql2 = ");
            out.write("\"");
            out.write(outstr.replace("\"", "\\\""));
            out.write("\"");
            out.newLine();
            out.close();
        }
        catch(Exception e)
        {
            e.printStackTrace();
        }


        try
        {
            System.out.println("writing to:" + workdir + File.separator + out_dir + tbl_stub_out);
            File d = new File(workdir + File.separator + out_dir);
            d.mkdirs();
            FileWriter fstream = new FileWriter(workdir + File.separator + out_dir + tbl_stub_out,
                StandardCharsets.UTF_8, true); // append!
            BufferedWriter out = new BufferedWriter(fstream);
            out.write("    {");
            out.newLine();
            out.write("    char *sql2 = \"");
            out.write(outstr.replace("\"", "\\\""));
            out.write("\"");
            out.newLine();
            out.close();
        }
        catch(Exception e)
        {
            e.printStackTrace();
        }
        tbl_runtime_incl_1 = "";
        tbl_runtime_incl_1 = read_text_file(proto_dir + File.separator  + runtime_header_table_in);
        tbl_runtime_incl_1 = tbl_runtime_incl_1.replace("__@@@TABLE@@@__", tablename)
                .replace("__@@@TABLEuc@@@__", tablename.toUpperCase())
                .replace("__@@@TABLElc@@@__", tablename.toLowerCase());
    }

    static void finish_table(final String workdir, final String tablename)
    {
        System.out.println("finishing: " + workdir + File.separator + out_dir + tablename + tbl_fh_ext);
        try
        {
            // write <Tablename>.h file
            File d = new File(workdir + File.separator + out_dir);
            d.mkdirs();
            final String tbl01 = read_text_file(proto_dir + tbl_h_proto);
            FileWriter fstream = new FileWriter(workdir + File.separator + out_dir + tablename + tbl_fh_ext,
                StandardCharsets.UTF_8);
            BufferedWriter out = new BufferedWriter(fstream);
            out.write(tbl01.replace("__@@@TABLE@@@__", tablename)
                .replace("__@@@TABLEuc@@@__", tablename.toUpperCase())
                .replace("__@@@TABLElc@@@__", tablename.toLowerCase())
                .replace("__@@@COLUMNS_STRUCT01@@@__", tbl_columns_for_struct_01)
                .replace("__@@@FUNCS_EQ@@@__", tbl_equalfuncs)
                .replace("__@@@FUNCS_SET@@@__", tbl_setfuncs)
                );
            out.newLine();
            out.close();
        }
        catch(Exception e)
        {
            e.printStackTrace();
        }

        System.out.println("finishing: " + workdir + File.separator + out_dir + tablename + tbl_fc_ext);
        try
        {
            // write <Tablename>.c file
            File d = new File(workdir + File.separator + out_dir);
            d.mkdirs();
            final String tbl01 = read_text_file(proto_dir + tbl_c_proto);
            FileWriter fstream = new FileWriter(workdir + File.separator + out_dir + tablename + tbl_fc_ext,
                StandardCharsets.UTF_8);
            BufferedWriter out = new BufferedWriter(fstream);
            tbl_inserters = tbl_inserters_a + tbl_inserters_b + tbl_inserters_c;
            out.write(tbl01.replace("__@@@TABLE@@@__", tablename)
                .replace("__@@@TABLEuc@@@__", tablename.toUpperCase())
                .replace("__@@@TABLElc@@@__", tablename.toLowerCase())
                .replace("__@@@COLUMNS_SETTERS_01@@@__", tbl_col_setters)
                .replace("__@@@COLUMNS_INSERTER_01@@@__", tbl_inserters)
                .replace("__@@@COLUMNS_INSERTER_BIND_02@@@__", tbl_inserter_bind)
                .replace("__@@@FUNCS_EQ03@@@__", tbl_equalfuncs_3)
                .replace("__@@@FUNCS_SET03@@@__", tbl_setfuncs_3)
                .replace("__@@@FUNCS_EQ02@@@__", tbl_equalfuncs_2)
                .replace("__@@@FUNCS_SET02@@@__", tbl_setfuncs_2)
                .replace("__@@@FUNCS_FREE_STRS01@@@__", tbl_freefuncs_1)
                );
            out.newLine();
            out.close();
        }
        catch(Exception e)
        {
            e.printStackTrace();
        }

        append_to_sql(workdir, tablename, "  PRIMARY KEY(\""+primary_key_column_name+"\""+primary_key_column_autoincr_if_needed_str+")");
        append_to_sql(workdir, tablename, ");");

        tbl_runtime_incl_1 = tbl_runtime_incl_1
                .replace("__@@@RT_COLUMNS_STRUCT20@@@__", tbl_columns_for_struct_01)
                .replace("__@@@RT_FUNCS_EQ20@@@__", tbl_equalfuncs)
                .replace("__@@@RT_FUNCS_SET20@@@__", tbl_setfuncs);

        tbl_runtime_incl_all += tbl_runtime_incl_1;

        mkf_tables_o_list += tablename + ".o ";

        mkf_tables_o_compile += "" + tablename + ".o" + ": " + tablename + ".c"+ " " +tablename + ".h" + "\n";
        mkf_tables_o_compile += "\t" + "$(CC) -c $(CFLAGS) $(LIBS) $< -o $@" + "\n";

        try
        {
            File d = new File(workdir + File.separator + out_dir);
            d.mkdirs();
            FileWriter fstream = new FileWriter(workdir + File.separator + out_dir + tablename + tbl_cs_ext,
                StandardCharsets.UTF_8, true); // append!
            BufferedWriter out = new BufferedWriter(fstream);
            out.write(";");
            out.newLine();
            out.write("}");
            out.newLine();
            out.close();
        }
        catch(Exception e)
        {
            e.printStackTrace();
        }


        try
        {
            File d = new File(workdir + File.separator + out_dir);
            d.mkdirs();
            FileWriter fstream = new FileWriter(workdir + File.separator + out_dir + tbl_stub_out,
                StandardCharsets.UTF_8, true); // append!
            BufferedWriter out = new BufferedWriter(fstream);
            out.write("    ;");
            out.newLine();
            out.write("    printf(\"STUB: creating table: " + tablename + "\\n\");");
            out.newLine();
            out.write("    CSORMA_GENERIC_RESULT res1 = OrmaDatabase_run_multi_sql(o, (const uint8_t *)sql2);");
            out.newLine();
            out.write("    printf(\"STUB: res1: %d\\n\", res1);");
            out.newLine();
            out.write("    }");
            out.newLine();
            out.close();
        }
        catch(Exception e)
        {
            e.printStackTrace();
        }
    }

    static void add_orderby_func(final String table_name, final String column_name, final COLTYPE ctype, final String ctype_firstupper)
    {
        final String column_name_firstupper = column_name.substring(0,1).toUpperCase() + column_name.substring(1);

        tbl_orderbyfuncs  += "" + "\n";
    }

    static void add_set_func02(final String table_name, final String column_name,
            final COLTYPE ctype, final String ctype_firstupper)
    {

String _f = """
static __@@@TABLE@@@__ *___@@@COLUMN_NAME@@@__Set(__@@@TABLE@@@__* t, __@@@CTYPE_CONST_CTYPE@@@__ __@@@CTYPE_CTYPE@@@__ __@@@COLUMN_NAME@@@__)
{
    if (t->sql_set->l == 0)
    {
        bind_to_set_sql___@@@CTYPE_BCSTYPE@@@__(t->sql_set, t->bind_set_vars, " set \\"__@@@COLUMN_NAME@@@__\\"=?", __@@@COLUMN_NAME@@@__, BINDVAR_TYPE___@@@CTYPE_CSTYPE@@@__);
    }
    else
    {
        bind_to_set_sql___@@@CTYPE_BCSTYPE@@@__(t->sql_set, t->bind_set_vars, " , \\"__@@@COLUMN_NAME@@@__\\"=?", __@@@COLUMN_NAME@@@__, BINDVAR_TYPE___@@@CTYPE_CSTYPE@@@__);
    }
    return t;
}
""";

        tbl_setfuncs_2  += r_(_f, table_name, column_name, ctype);
        tbl_setfuncs_2  += "" + "\n";
    }

    static void add_set_func(final String table_name, final String column_name, final COLTYPE ctype, final String ctype_firstupper)
    {
        // Message* (*message_idSet)(Message *m, const int64_t message_id);
        // Message* (*readSet)(Message *m, const bool read);
        // Message* (*textSet)(Message *m, csorma_s *text);

        if ((ctype == COLTYPE.INT)||(ctype == COLTYPE.LONG))
        {
            tbl_setfuncs  += "    " + table_name + "* (*" + lc(column_name) + "Set)(" + table_name + " *t, const " +
                ctype.ctype + " " + lc(column_name) + ");";
        }
        else if (ctype == COLTYPE.BOOLEAN)
        {
            tbl_setfuncs  += "    " + table_name + "* (*" + lc(column_name) + "Set)(" + table_name + " *t, const " +
                ctype.ctype + " " + lc(column_name) + ");";
        }
        else if (ctype == COLTYPE.STRING)
        {
            tbl_setfuncs  += "    " + table_name + "* (*" + lc(column_name) + "Set)(" + table_name + " *t, " +
                ctype.ctype + " " + lc(column_name) + ");";
        }

        tbl_setfuncs  += "" + "\n";
    }

    static void add_set_func03(final String table_name, final String column_name,
            final COLTYPE ctype, final String ctype_firstupper)
    {
        if ((ctype == COLTYPE.INT)||(ctype == COLTYPE.LONG))
        {
            tbl_setfuncs_3  += "    " + table_name + "* (*_FuncPtr0030_" + lc(column_name) +
                ") (" + table_name + "*, const " + ctype.ctype + ");\n";
            tbl_setfuncs_3  += "    " + "_FuncPtr0030_" + lc(column_name) + " = &_" + lc(column_name) + "Set;" + "\n";
            tbl_setfuncs_3  += "    " + "t->" + lc(column_name) + "Set = _FuncPtr0030_" + lc(column_name)  + ";\n";
        }
        else if (ctype == COLTYPE.BOOLEAN)
        {
            tbl_setfuncs_3  += "    " + table_name + "* (*_FuncPtr0030_" + lc(column_name) +
                ") (" + table_name + "*, const " + ctype.ctype + ");\n";
            tbl_setfuncs_3  += "    " + "_FuncPtr0030_" + lc(column_name) + " = &_" + lc(column_name) + "Set;" + "\n";
            tbl_setfuncs_3  += "    " + "t->" + lc(column_name) + "Set = _FuncPtr0030_" + lc(column_name)  + ";\n";
        }
        else if (ctype == COLTYPE.STRING)
        {
            tbl_setfuncs_3  += "    " + table_name + "* (*_FuncPtr0030_" + lc(column_name) +
                ") (" + table_name + "*, " + ctype.ctype + ");\n";
            tbl_setfuncs_3  += "    " + "_FuncPtr0030_" + lc(column_name) + " = &_" + lc(column_name) + "Set;" + "\n";
            tbl_setfuncs_3  += "    " + "t->" + lc(column_name) + "Set = _FuncPtr0030_" + lc(column_name)  + ";\n";
        }

        tbl_setfuncs_3  += "    " + "// ------------" + "\n";
    }

    static void add_equal_func03(final String table_name, final String column_name,
            final COLTYPE ctype, final String ctype_firstupper)
    {
        String[] list = new String[]{"Eq","NotEq","Lt","Le","Gt","Ge"};
        for (String cmp_str : list)
        {
            if ((ctype == COLTYPE.INT)||(ctype == COLTYPE.LONG)||(ctype == COLTYPE.BOOLEAN))
            {
                tbl_equalfuncs_3  += "    " + table_name + "* (*_FuncPtr0020_"+cmp_str+"" + lc(column_name) +
                    ") (" + table_name + "*, const " + ctype.ctype + ");\n";
                tbl_equalfuncs_3  += "    " + "_FuncPtr0020_"+cmp_str+"" + lc(column_name) + " = &_" + lc(column_name) + ""+cmp_str+";" + "\n";
                tbl_equalfuncs_3  += "    " + "t->" + lc(column_name) + ""+cmp_str+" = _FuncPtr0020_"+cmp_str+"" + lc(column_name)  + ";\n";
            }
            else if (ctype == COLTYPE.STRING)
            {
                tbl_equalfuncs_3  += "    " + table_name + "* (*_FuncPtr0020_"+cmp_str+"" + lc(column_name) +
                    ") (" + table_name + "*, " + ctype.ctype + ");\n";
                tbl_equalfuncs_3  += "    " + "_FuncPtr0020_"+cmp_str+"" + lc(column_name) + " = &_" + lc(column_name) + ""+cmp_str+";" + "\n";
                tbl_equalfuncs_3  += "    " + "t->" + lc(column_name) + ""+cmp_str+" = _FuncPtr0020_"+cmp_str+"" + lc(column_name)  + ";\n";
            }
        }

        list = new String[]{"Like","NotLike"};
        for (String cmp_str : list)
        {
            // like and notlike always requires a string argument
            tbl_equalfuncs_3  += "    " + table_name + "* (*_FuncPtr0020_"+cmp_str+"" + lc(column_name) +
                ") (" + table_name + "*, " + "csorma_s *" + ");\n";
            tbl_equalfuncs_3  += "    " + "_FuncPtr0020_"+cmp_str+"" + lc(column_name) + " = &_" + lc(column_name) + ""+cmp_str+";" + "\n";
            tbl_equalfuncs_3  += "    " + "t->" + lc(column_name) + ""+cmp_str+" = _FuncPtr0020_"+cmp_str+"" + lc(column_name)  + ";\n";
        }

        String[] list3 = new String[]{"IsNull","IsNotNull"};
        for (String cmp_str : list3)
        {
            tbl_equalfuncs_3  += "    " + table_name + "* (*_FuncPtr0020_"+cmp_str+"" + lc(column_name) +
                ") (" + table_name + "*);\n";
            tbl_equalfuncs_3  += "    " + "_FuncPtr0020_"+cmp_str+"" + lc(column_name) + " = &_" + lc(column_name) + ""+cmp_str+";" + "\n";
            tbl_equalfuncs_3  += "    " + "t->" + lc(column_name) + ""+cmp_str+" = _FuncPtr0020_"+cmp_str+"" + lc(column_name)  + ";\n";
        }

        String[] list2 = new String[]{"Asc", "Desc"};
        for (String cmp_str : list2)
        {
            tbl_equalfuncs_3  += "    " + table_name + "* (*_FuncPtr0020_"+cmp_str+"" + lc(column_name) +
                ") (" + table_name + "*);\n";
            tbl_equalfuncs_3  += "    " + "_FuncPtr0020_"+cmp_str+"" + lc(column_name) + " = &_orderBy" + lc(column_name) + ""+cmp_str+";" + "\n";
            tbl_equalfuncs_3  += "    " + "t->orderBy" + lc(column_name) + ""+cmp_str+" = _FuncPtr0020_"+cmp_str+"" + lc(column_name)  + ";\n";
        }

        tbl_equalfuncs_3  += "    " + "// ------------" + "\n";
    }

    static void add_equal_func02(final String table_name, final String column_name,
            final COLTYPE ctype, final String ctype_firstupper)
    {

String _f_eq = """
static __@@@TABLE@@@__ *___@@@COLUMN_NAME@@@__Eq(__@@@TABLE@@@__ *t, __@@@CTYPE_CONST_CTYPE@@@__ __@@@CTYPE_CTYPE@@@__ __@@@COLUMN_NAME@@@__)
{
    bind_to_where_sql___@@@CTYPE_BCSTYPE@@@__(t->sql_where, t->bind_where_vars, "and \\"__@@@COLUMN_NAME@@@__\\"=?", __@@@COLUMN_NAME@@@__, BINDVAR_TYPE___@@@CTYPE_CSTYPE@@@__, "");
    return t;
}
""";

String _f_neq = """
static __@@@TABLE@@@__ *___@@@COLUMN_NAME@@@__NotEq(__@@@TABLE@@@__ *t, __@@@CTYPE_CONST_CTYPE@@@__ __@@@CTYPE_CTYPE@@@__ __@@@COLUMN_NAME@@@__)
{
    bind_to_where_sql___@@@CTYPE_BCSTYPE@@@__(t->sql_where, t->bind_where_vars, "and \\"__@@@COLUMN_NAME@@@__\\"<>?", __@@@COLUMN_NAME@@@__, BINDVAR_TYPE___@@@CTYPE_CSTYPE@@@__, "");
    return t;
}
""";

String _f_lt = """
static __@@@TABLE@@@__ *___@@@COLUMN_NAME@@@__Lt(__@@@TABLE@@@__ *t, __@@@CTYPE_CONST_CTYPE@@@__ __@@@CTYPE_CTYPE@@@__ __@@@COLUMN_NAME@@@__)
{
    bind_to_where_sql___@@@CTYPE_BCSTYPE@@@__(t->sql_where, t->bind_where_vars, "and \\"__@@@COLUMN_NAME@@@__\\"<?", __@@@COLUMN_NAME@@@__, BINDVAR_TYPE___@@@CTYPE_CSTYPE@@@__, "");
    return t;
}
""";

String _f_le = """
static __@@@TABLE@@@__ *___@@@COLUMN_NAME@@@__Le(__@@@TABLE@@@__ *t, __@@@CTYPE_CONST_CTYPE@@@__ __@@@CTYPE_CTYPE@@@__ __@@@COLUMN_NAME@@@__)
{
    bind_to_where_sql___@@@CTYPE_BCSTYPE@@@__(t->sql_where, t->bind_where_vars, "and \\"__@@@COLUMN_NAME@@@__\\"<=?", __@@@COLUMN_NAME@@@__, BINDVAR_TYPE___@@@CTYPE_CSTYPE@@@__, "");
    return t;
}
""";

String _f_gt = """
static __@@@TABLE@@@__ *___@@@COLUMN_NAME@@@__Gt(__@@@TABLE@@@__ *t, __@@@CTYPE_CONST_CTYPE@@@__ __@@@CTYPE_CTYPE@@@__ __@@@COLUMN_NAME@@@__)
{
    bind_to_where_sql___@@@CTYPE_BCSTYPE@@@__(t->sql_where, t->bind_where_vars, "and \\"__@@@COLUMN_NAME@@@__\\">?", __@@@COLUMN_NAME@@@__, BINDVAR_TYPE___@@@CTYPE_CSTYPE@@@__, "");
    return t;
}
""";

String _f_ge = """
static __@@@TABLE@@@__ *___@@@COLUMN_NAME@@@__Ge(__@@@TABLE@@@__ *t, __@@@CTYPE_CONST_CTYPE@@@__ __@@@CTYPE_CTYPE@@@__ __@@@COLUMN_NAME@@@__)
{
    bind_to_where_sql___@@@CTYPE_BCSTYPE@@@__(t->sql_where, t->bind_where_vars, "and \\"__@@@COLUMN_NAME@@@__\\">=?", __@@@COLUMN_NAME@@@__, BINDVAR_TYPE___@@@CTYPE_CSTYPE@@@__, "");
    return t;
}
""";

String _f_like = """
static __@@@TABLE@@@__ *___@@@COLUMN_NAME@@@__Like(__@@@TABLE@@@__ *t, csorma_s * __@@@COLUMN_NAME@@@__)
{
    bind_to_where_sql_string(t->sql_where, t->bind_where_vars, "and \\"__@@@COLUMN_NAME@@@__\\" LIKE ?", __@@@COLUMN_NAME@@@__, BINDVAR_TYPE_String, (const char*)" ESCAPE '\\\\' ");
    return t;
}
""";

String _f_notlike = """
static __@@@TABLE@@@__ *___@@@COLUMN_NAME@@@__NotLike(__@@@TABLE@@@__ *t, csorma_s * __@@@COLUMN_NAME@@@__)
{
    bind_to_where_sql_string(t->sql_where, t->bind_where_vars, "and \\"__@@@COLUMN_NAME@@@__\\" NOT LIKE ?", __@@@COLUMN_NAME@@@__, BINDVAR_TYPE_String, (const char*)" ESCAPE '\\\\' ");
    return t;
}
""";

String _f_null = """
static __@@@TABLE@@@__ *___@@@COLUMN_NAME@@@__IsNull(__@@@TABLE@@@__ *t)
{
    add_to_where_sql_string(t->sql_where, "and \\"__@@@COLUMN_NAME@@@__\\" IS NULL");
    return t;
}
""";

String _f_notnull = """
static __@@@TABLE@@@__ *___@@@COLUMN_NAME@@@__IsNotNull(__@@@TABLE@@@__ *t)
{
    add_to_where_sql_string(t->sql_where, "and \\"__@@@COLUMN_NAME@@@__\\" IS NOT NULL");
    return t;
}
""";

String _f_orderbyasc = """
static __@@@TABLE@@@__ *_orderBy__@@@COLUMN_NAME@@@__Asc(__@@@TABLE@@@__ *t)
{
    add_to_orderby_asc_sql(t->sql_orderby, "\\"__@@@COLUMN_NAME@@@__\\"", true);
    return t;
}
""";

String _f_orderbydesc = """
static __@@@TABLE@@@__ *_orderBy__@@@COLUMN_NAME@@@__Desc(__@@@TABLE@@@__ *t)
{
    add_to_orderby_asc_sql(t->sql_orderby, "\\"__@@@COLUMN_NAME@@@__\\"", false);
    return t;
}
""";

        tbl_equalfuncs_2  += r_(_f_eq, table_name, column_name, ctype);
        tbl_equalfuncs_2  += r_(_f_neq, table_name, column_name, ctype);
        tbl_equalfuncs_2  += r_(_f_lt, table_name, column_name, ctype);
        tbl_equalfuncs_2  += r_(_f_le, table_name, column_name, ctype);
        tbl_equalfuncs_2  += r_(_f_gt, table_name, column_name, ctype);
        tbl_equalfuncs_2  += r_(_f_ge, table_name, column_name, ctype);
        tbl_equalfuncs_2  += r_(_f_like, table_name, column_name, ctype);
        tbl_equalfuncs_2  += r_(_f_notlike, table_name, column_name, ctype);
        tbl_equalfuncs_2  += r_(_f_null, table_name, column_name, ctype);
        tbl_equalfuncs_2  += r_(_f_notnull, table_name, column_name, ctype);
        tbl_equalfuncs_2  += r_(_f_orderbyasc, table_name, column_name, ctype);
        tbl_equalfuncs_2  += r_(_f_orderbydesc, table_name, column_name, ctype);
    }

    static void add_equal_func(final String table_name, final String column_name, final COLTYPE ctype, final String ctype_firstupper)
    {

        if ((ctype == COLTYPE.INT)||(ctype == COLTYPE.LONG)||(ctype == COLTYPE.BOOLEAN))
        {
            tbl_equalfuncs  += "    " + table_name + "* (*" + lc(column_name) + "Eq)(" + table_name + " *t, const " +
                ctype.ctype + " " + lc(column_name) + ");" + "\n";
            tbl_equalfuncs  += "    " + table_name + "* (*" + lc(column_name) + "NotEq)(" + table_name + " *t, const " +
                ctype.ctype + " " + lc(column_name) + ");" + "\n";
            tbl_equalfuncs  += "    " + table_name + "* (*" + lc(column_name) + "Lt)(" + table_name + " *t, const " +
                ctype.ctype + " " + lc(column_name) + ");" + "\n";
            tbl_equalfuncs  += "    " + table_name + "* (*" + lc(column_name) + "Le)(" + table_name + " *t, const " +
                ctype.ctype + " " + lc(column_name) + ");" + "\n";
            tbl_equalfuncs  += "    " + table_name + "* (*" + lc(column_name) + "Gt)(" + table_name + " *t, const " +
                ctype.ctype + " " + lc(column_name) + ");" + "\n";
            tbl_equalfuncs  += "    " + table_name + "* (*" + lc(column_name) + "Ge)(" + table_name + " *t, const " +
                ctype.ctype + " " + lc(column_name) + ");" + "\n";
        }
        else if (ctype == COLTYPE.STRING)
        {
            tbl_equalfuncs  += "    " + table_name + "* (*" + lc(column_name) + "Eq)(" + table_name + " *t, " +
                ctype.ctype + " " + lc(column_name) + ");" + "\n";
            tbl_equalfuncs  += "    " + table_name + "* (*" + lc(column_name) + "NotEq)(" + table_name + " *t, " +
                ctype.ctype + " " + lc(column_name) + ");" + "\n";
            tbl_equalfuncs  += "    " + table_name + "* (*" + lc(column_name) + "Lt)(" + table_name + " *t, " +
                ctype.ctype + " " + lc(column_name) + ");" + "\n";
            tbl_equalfuncs  += "    " + table_name + "* (*" + lc(column_name) + "Le)(" + table_name + " *t, " +
                ctype.ctype + " " + lc(column_name) + ");" + "\n";
            tbl_equalfuncs  += "    " + table_name + "* (*" + lc(column_name) + "Gt)(" + table_name + " *t, " +
                ctype.ctype + " " + lc(column_name) + ");" + "\n";
            tbl_equalfuncs  += "    " + table_name + "* (*" + lc(column_name) + "Ge)(" + table_name + " *t, " +
                ctype.ctype + " " + lc(column_name) + ");" + "\n";
        }

        tbl_equalfuncs  += "    " + table_name + "* (*" + lc(column_name) + "IsNull)(" + table_name + " *t);" + "\n";
        tbl_equalfuncs  += "    " + table_name + "* (*" + lc(column_name) + "IsNotNull)(" + table_name + " *t);" + "\n";

        tbl_equalfuncs  += "    " + table_name + "* (*" + lc(column_name) + "Like)(" + table_name + " *t, " +
            "csorma_s *" + " " + lc(column_name) + ");" + "\n";
        tbl_equalfuncs  += "    " + table_name + "* (*" + lc(column_name) + "NotLike)(" + table_name + " *t, " +
            "csorma_s *" + " " + lc(column_name) + ");" + "\n";

        tbl_equalfuncs  += "    " + table_name + "* (*orderBy" + lc(column_name) + "Asc)(" + table_name + " *t);" + "\n";
        tbl_equalfuncs  += "    " + table_name + "* (*orderBy" + lc(column_name) + "Desc)(" + table_name + " *t);" + "\n";
    }

    static String remove_public(final String in)
    {
        if (in.trim().startsWith("public"))
        {
            return in.trim().substring("public".length()).trim();
        }
        else
        {
            return in;
        }
    }

    static String remove_type(final String in)
    {
        if (in.trim().toLowerCase().startsWith("int"))
        {
            return in.trim().substring("int".length()).trim();
        }
        else if (in.trim().toLowerCase().startsWith("long"))
        {
            return in.trim().substring("long".length()).trim();
        }
        else if (in.trim().toLowerCase().startsWith("string"))
        {
            return in.trim().substring("string".length()).trim();
        }
        else if (in.trim().toLowerCase().startsWith("boolean"))
        {
            return in.trim().substring("boolean".length()).trim();
        }
        else
        {
            return in;
        }
    }

    public static int min3(int a, int b, int c) {
        return Math.min(Math.min(a, b), c);
    }

    static String get_name(final String in)
    {
        String tmp = in.trim();
        int i1 = 999;
        int i2 = 999;
        int i3 = 999;
        try
        {
            i1 = tmp.indexOf(" ");
            if (i1<1){i1=999;}
        }
        catch(Exception e)
        {}
        try
        {
            i2 = tmp.indexOf("=");
            if (i2<1){i2=999;}
        }
        catch(Exception e)
        {}
        try
        {
            i3 = tmp.indexOf(";");
            if (i1<3){i3=999;}
        }
        catch(Exception e)
        {}

        // System.out.println(""+ i1 + " " + i2 + " " + i3 + " min=" + min3(i1, i2, i3));
        return tmp.substring(0, min3(i1, i2, i3)).trim();
    }

    static COLTYPE get_type(final String in)
    {
        if (in.trim().toLowerCase().startsWith("long"))
        {
            return COLTYPE.LONG;
        }
        else if (in.trim().toLowerCase().startsWith("int"))
        {
            return COLTYPE.INT;
        }
        else if (in.trim().toLowerCase().startsWith("string"))
        {
            return COLTYPE.STRING;
        }
        else if (in.trim().toLowerCase().startsWith("boolean"))
        {
            return COLTYPE.BOOLEAN;
        }
        return COLTYPE.UNKNOWN;
    }

    static void append_to_sql(final String workdir, final String tablename, final String txt_line)
    {
        // System.out.println("appending to table: " + workdir + File.separator + out_dir + tablename + tbl_s_ext);
        try
        {
            File d = new File(workdir + File.separator + out_dir);
            d.mkdirs();
            FileWriter fstream = new FileWriter(workdir + File.separator + out_dir + tablename + tbl_s_ext,
                StandardCharsets.UTF_8, true); // append!
            BufferedWriter out = new BufferedWriter(fstream);
            out.write(txt_line);
            out.newLine();
            out.close();

            fstream = new FileWriter(workdir + File.separator + out_dir + tablename + tbl_cs_ext,
                StandardCharsets.UTF_8, true); // append!
            out = new BufferedWriter(fstream);
            out.write("\"");
            out.write(txt_line.replace("\"", "\\\""));
            out.write("\"");
            out.newLine();
            out.close();
        }
        catch(Exception e)
        {
            e.printStackTrace();
        }


        try
        {
            File d = new File(workdir + File.separator + out_dir);
            d.mkdirs();
            FileWriter fstream = new FileWriter(workdir + File.separator + out_dir + tbl_stub_out,
                StandardCharsets.UTF_8, true); // append!
            BufferedWriter out = new BufferedWriter(fstream);
            out.write("    \"");
            out.write("    "+txt_line.replace("\"", "\\\""));
            out.write("    \"");
            out.newLine();
            out.close();
        }
        catch(Exception e)
        {
            e.printStackTrace();
        }
    }

    static void append_to_table(final String workdir, final String tablename, final String txt_line)
    {
        // System.out.println("appending to table: " + workdir + File.separator + out_dir + tablename + tbl_fh_ext);
        try
        {
            File d = new File(workdir + File.separator + out_dir);
            d.mkdirs();
            FileWriter fstream = new FileWriter(workdir + File.separator + out_dir + tablename + tbl_fh_ext,
                StandardCharsets.UTF_8, true); // append!
            BufferedWriter out = new BufferedWriter(fstream);
            out.write(txt_line);
            out.newLine();
            out.close();
        }
        catch(Exception e)
        {
            e.printStackTrace();
        }
    }

    static String read_text_file(final String filename_with_path)
    {
        Path filePath = Path.of(filename_with_path);
            StringBuilder contentBuilder = new StringBuilder();
        try (Stream<String> stream = Files.lines(filePath, StandardCharsets.UTF_8))
        {
            stream.forEach(s -> contentBuilder.append(s).append("\n"));
        } catch (Exception e)
        {
        }
        return contentBuilder.toString();
    }

}
