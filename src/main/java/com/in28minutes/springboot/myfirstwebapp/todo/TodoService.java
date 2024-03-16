package com.in28minutes.springboot.myfirstwebapp.todo;

import jakarta.validation.Valid;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Predicate;

@Service
public class TodoService {

    private static int todosCount = 0;
    private static List<Todo> todos = new ArrayList<>();
    static {
        todos.add(new Todo(++todosCount, "Ravi", "Learn spring boot", LocalDate.now().plusMonths(6), false));
        todos.add(new Todo(++todosCount, "Ravi", "Learn full stack", LocalDate.now().plusMonths(12), false));
        todos.add(new Todo(++todosCount, "Ravi", "Learn java script", LocalDate.now().plusMonths(4), false));
    }

    public List<Todo> findByUsername(String userName) {
        Predicate<? super Todo> predicate = todo -> todo.getUsername().equalsIgnoreCase(userName);
        return todos.stream().filter(predicate).toList();
    }

    public void addTodo(String username, String description, LocalDate targetDate, boolean done) {
        Todo todo = new Todo(++todosCount,username,description,targetDate,done);
        todos.add(todo);
    }

    public void deleteById(int id) {
        //todo.getId() == id
        // todo -> todo.getId() == id
        Predicate<? super Todo> predicate = todo -> todo.getId() == id;
        todos.removeIf(predicate);
    }

    public Todo findById(int id) {
        Predicate<? super Todo> predicate = todo -> todo.getId() == id;
        Todo todo = todos.stream().filter(predicate).findFirst().get();
        return todo;
    }

    public void updateTodo(@Valid Todo todo) {
        deleteById(todo.getId());
        todos.add(todo);
    }
}
