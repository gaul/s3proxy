package org.gaul.s3proxy.extend;


import com.google.common.collect.ImmutableMap;
import org.jclouds.blobstore.BlobStore;

import java.sql.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @author yangyanbo
 */
public class SqliteAKSKManager extends AbStractAKSKManager {
    String defaultConf = "src/main/resources/config.db";
    Connection conn = null;

    public SqliteAKSKManager(String configPath) throws SQLException {
        super();
        if (configPath.equalsIgnoreCase("")) {
            configPath = defaultConf;
        }
        String dbUrl = "jdbc:sqlite:" + configPath;
        conn = DriverManager.getConnection(dbUrl);
        if (conn != null) {
            DatabaseMetaData meta = conn.getMetaData();
            System.out.println("The driver name is " + meta.getDriverName());
            System.out.println("A new database has been created.");
        }
        this.createTable();
        this.insertSomeUsers();
        this.loads2Cache();
    }

    @Override
    public void createAKSKForBucket(String bucket, String access_key, String secret_key) {
        try {
            String sql = "INSERT INTO bucket_access_manage(bucket, access_key, secret_key) VALUES(?,?, ?)";
            PreparedStatement pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, bucket);
            pstmt.setString(2, access_key);
            pstmt.setString(3, secret_key);
            pstmt.executeUpdate();
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    @Override
    public Map<String, AkSkPair> loads2Cache() {
        try {
            Map<String, AkSkPair> bucketAkList = this.getBucketAkSKsFromDB();
            for (String key : bucketAkList.keySet()) {
                this.getCacheManager().setKey(key, bucketAkList.get(key));
            }
            return bucketAkList;
        } catch (Exception e) {
            System.out.println("Take record from db to cache fail.");
            return null;
        }

    }

    @Override
    public Map<String, AkSkPair> getBucketAkSkList() throws Exception {
        // first take from cache. if not take from db
        Map<String, AkSkPair> map = new HashMap<>();
        Map<String, Object> m = this.getCacheManager().getAll();
        for (String key : m.keySet()) {
            map.put(key, (AkSkPair) m.get(key));
        }
        return map;
    }

    @Override
    public String getBucketFromAccessKey(String ak) {
        // ugly here but work
        String bucket = "";
        try {
            Map<String, Object> m = this.getCacheManager().getAll();
            for (String k : m.keySet()) {
                AkSkPair akSkPair = (AkSkPair) m.get(k);
                if (akSkPair.getAccess_key().equalsIgnoreCase(ak)) {
                    bucket = k;
                    break;
                }
            }

        } catch (Exception e) {
            e.printStackTrace();
            return bucket;
        } finally {
            return bucket;
        }
    }

    public void createTable() {
        try {
            // SQL statement for creating a new table
            String sql = "CREATE TABLE IF NOT EXISTS bucket_access_manage (\n"
                    + " id integer PRIMARY KEY,\n"
                    + " bucket text UNIQUE NOT NULL,\n"
                    + " access_key text UNIQUE NOT NULL,\n"
                    + " secret_key text NOT NULL,\n"
                    + " enable integer\n"
                    + ");";
            Statement stmt = conn.createStatement();
            stmt.execute(sql);
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    public Map<String, AkSkPair> getBucketAkSKsFromDB() throws Exception {
        String sql = "SELECT id, bucket, access_key,secret_key FROM bucket_access_manage";
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery(sql);
        Map<String, AkSkPair> rsl = new HashMap<>();
        // loop through the result set
        while (rs.next()) {
            System.out.println(rs.getInt("id") + "\t" +
                    rs.getString("bucket") + "\t" +
                    rs.getString("access_key") + "\t" +
                    rs.getString("secret_key"));

            AkSkPair akSkPair = new AkSkPair(rs.getString("access_key"),
                    rs.getString("secret_key"));

            rsl.put(rs.getString("bucket"), akSkPair);
        }
        return rsl;
    }

    public void insertSomeUsers() {
        // SQL statement for creating a new table
        try {
            this.createAKSKForBucket("test1", "cccccc", "ZDU3NzI3M2ZmODg1YzNmODRkYWRiODU3OGJiNDEzOTkgIC0K");
            this.createAKSKForBucket("test", "test", "NzIzZWU2ZmUyNjlkYjAzZDQ5YTllMjA0MTYwZGYzNGQgIC0K");
            this.createAKSKForBucket("test3", "helloworld3", "1234512345");
        } catch (Exception e) {
            e.printStackTrace();
        }


    }


}
