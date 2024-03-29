<%@ taglib prefix="c" uri="jakarta.tags.core" %>

<html>
	<head>
		<link href="webjars/bootstrap/5.1.3/css/bootstrap.min.css" rel="stylesheet" >
		<title>List Todos Page</title>
	</head>
	<body>
		<div class="container">
		    <nav class="navbar navbar-expand-md navbar-light bg-light mb-3 p-1">
            	<a class="navbar-brand m-1" href="https://www.linkedin.com/in/ravi-raj-aa2555212/">Ravi Todos</a>
            	<div class="collapse navbar-collapse">
            		<ul class="navbar-nav">
            			<li class="nav-item"><a class="nav-link" href="/">Home</a></li>
            			<li class="nav-item"><a class="nav-link" href="/list-todos">Todos</a></li>
            		</ul>
            	</div>
            	<ul class="navbar-nav">
            		<li class="nav-item"><a class="nav-link" href="/logout">Logout</a></li>
            	</ul>
            </nav>

			<h1>Your Todos</h1>
			<table class="table">
				<thead>
					<tr>
						<th>id</th>
						<th>Description</th>
						<th>Target Date</th>
						<th>Is Done?</th>
					</tr>
				</thead>
				<tbody>
					<c:forEach items="${todos}" var="todo">
						<tr>
							<td>${todo.description}</td>
							<td>${todo.targetDate}</td>
							<td>${todo.done}</td>
							<td> <a href="delete-todo?id=${todo.id}" class = "btn btn-warning"> DELETE </a> </td>
							<td> <a href="update-todo?id=${todo.id}" class="btn btn-success">Update</a>   </td>
						</tr>
					</c:forEach>
				</tbody>
			</table>
			<a href = "add-todo" class="btn btn-success"> Add Todo </a>

		</div>
		<script src="webjars/bootstrap/5.1.3/js/bootstrap.min.js"></script>
		<script src="webjars/jquery/3.6.0/jquery.min.js"></script>

	</body>
</html>