import { Component } from '@angular/core';
import { MatIconModule } from '@angular/material/icon';
import { SideNavComponent } from '../side-nav/side-nav.component';
import { CommonModule } from '@angular/common';
import { Router } from '@angular/router';

@Component({
  selector: 'app-dashboard',
  standalone: true,
  imports: [MatIconModule, SideNavComponent, CommonModule],
  templateUrl: './dashboard.component.html',
  styleUrl: './dashboard.component.scss'
})

export class DashboardComponent {
  // income
  lastMonthsIncome = ['January: $1000', 'Februray: $1500', 'March: $1200'];
  currentMonthsIncome = '$2000';

  // Expense
  lastMonthsExpense = ['January: $800', 'Februray: $1000', 'March: $1200'];
  currentMonthsExpense = '$1500';

  //To-do Transactions
  todoTransactions =[
    { description: 'pay electricity bills'},
    { description: 'Submit monthly report'},
    { description: 'Buy Groceries'},
    { description: 'call insurance company'}
  ];
  
  totalCurrentMonthIncome = 2000;
  totalCurrentMonthExpense = 1500;
    

  constructor(public router: Router) { }
  onIncome() {
    this.router.navigate(['/portfolio-website/income']);
  }

  onExpense() {
    this.router.navigate(['/portfolio-website/expense']);
  }

  ontodo(){
    this.router.navigate(['/portfolio-website/todo']);
  }

get currentMonthSavings(): number {
  return this.totalCurrentMonthIncome -this.totalCurrentMonthExpense;
}
}

