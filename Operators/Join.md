# Join Operator

The `Join` Operator merges the rows of two tables to form a new table by matching values of the specified column from each table.

Kusto Query Language (KQL) offers many kinds of joins that each affect the schema and rows in the resultant table in different ways. For example, if you use an inner join, the table has the same columns as the left table, plus the columns from the right table. For best performance, if one table is always smaller than the other, use it as the left side of the join operator.

## Syntax

LeftTable | join [ kind = JoinFlavor ] [ Hints ] (RightTable) on Conditions


## Tyes of Join:

Consider these two tables to understand the below type of join:

#### Users Table (Left Table):

UserID | UserName
-------|---------
1      | Alice
2      | Bob
3      | Charlie
4      | David

#### Logons (Right Table)

UserID | DeviceName
-------|------------
1      | Laptop
1      | Mobile
2      | Tablet
5      | Laptop


### Left Outer :

All rows from the left table plus matches from the right, Non-matcges on the right show as Null.

```kql
Users
| join kind=leftouter Logons on UserID
```

#### Results

| UserID | Username | DeviceName |
|--------|----------|------------|
|  1     | Alice    |  Laptop    |
|  1     | Alice    |  Mobile    |
|  2     | Bob      |  Tablet    |  
|  3     | Charlie  |  Null      |
|  4     | David    |  Null      |

### Full Outer :

Keep Everything rom both the sides.

```kql
Users
| join kind=fullouter Logons on UserID
```

#### Results

| UserID | Username | DeviceName |
|--------|----------|------------|
|   1    | Alice    | Laptop     |
|   1    | Alice    | Mobile     |
|   2    | Bob      |   Tablet   |
|   3    | Charlie  |    null    |
|   4    | David    |    Null    |
|   5    | Null     |  Laptop    |

### Right Outer 

All rows from Logons, plus matches from users 

```kql
Users
| join kind=rightouter Logons on UserID
```

#### Results


| UserID |UserName | DeviceName |
|--------|---------|------------|
| 1 |	Alice |	Laptop|
| 1 |	Alice | Mobile|
| 2	 | Bob | Tablet |
| 5	| (null)	| Laptop |

