/*
 * Copyright (C) 2026 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package store

import (
	"context"
	"database/sql"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nethesis/nethcti-middleware/db"
)

func TestListUserSettings(t *testing.T) {
	database := db.GetDB()
	_, err := database.Exec("CREATE TABLE IF NOT EXISTS `user_settings` (`id` int(11) NOT NULL AUTO_INCREMENT, `username` varchar(50) NOT NULL, `key_name` varchar(50) NOT NULL, `value` mediumtext, PRIMARY KEY (`id`), UNIQUE KEY `username_key_name` (`username`,`key_name`)) ENGINE=MyISAM DEFAULT CHARSET=utf8")
	require.NoError(t, err)
	_, err = database.Exec("DELETE FROM `user_settings`")
	require.NoError(t, err)
	defer database.Exec("DELETE FROM `user_settings`")

	_, err = database.Exec("INSERT INTO `user_settings` (`username`, `key_name`, `value`) VALUES ('alice', 'avatar', 'a'), ('bob', 'theme', NULL)")
	require.NoError(t, err)

	settings, err := ListUserSettings(context.Background())

	require.NoError(t, err)
	assert.Equal(t, []UserSettingRow{
		{Username: "alice", KeyName: "avatar", Value: sql.NullString{String: "a", Valid: true}},
		{Username: "bob", KeyName: "theme"},
	}, settings)
}

func TestGetProfileParamURL(t *testing.T) {
	database := db.GetDB()
	_, err := database.Exec("CREATE DATABASE IF NOT EXISTS asterisk")
	require.NoError(t, err)
	_, err = database.Exec("CREATE TABLE IF NOT EXISTS " + profileParamURLTable + " (`id` int(10) unsigned NOT NULL AUTO_INCREMENT, `profile_id` int(10) unsigned NOT NULL, `url` varchar(255) NOT NULL DEFAULT '', `only_queues` tinyint(1) NOT NULL DEFAULT '0', PRIMARY KEY (`id`), UNIQUE KEY `profile_id_key` (`profile_id`)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4")
	require.NoError(t, err)
	_, err = database.Exec("DELETE FROM " + profileParamURLTable)
	require.NoError(t, err)
	defer database.Exec("DELETE FROM " + profileParamURLTable)

	_, err = database.Exec("INSERT INTO "+profileParamURLTable+" (`id`, `profile_id`, `url`, `only_queues`) VALUES (4294967295, 3, ?, 1)", "https://crm.it/?n=$CALLER_NUMBER")
	require.NoError(t, err)

	paramURL, err := GetProfileParamURL(context.Background(), "3")
	require.NoError(t, err)
	assert.Equal(t, &ProfileParamURL{ID: 4294967295, ProfileID: 3, URL: "https://crm.it/?n=$CALLER_NUMBER", OnlyQueues: 1}, paramURL)

	missing, err := GetProfileParamURL(context.Background(), "4")
	require.NoError(t, err)
	assert.Nil(t, missing)
}
